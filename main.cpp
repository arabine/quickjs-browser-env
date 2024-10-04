/* This is a minimal example of a program that just uses the QuickJS library
   to print "Hello".   
   
   There was a lack (at least on the QuickJS project page) of a simple sample
   in C that demonstrates how one could embed QuickJS in a project.  So I
   wrote one.
   
   It borrows heavily from qjs.c in the original project
   but pulls only the essentials out for a "hello world" type demo.
   https://bellard.org/quickjs/
*/
   
#include "quickjs.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "civetweb.h"
#include <memory.h>


#include "cutils.h"
#include "quickjs-libc.h"

#if defined(__APPLE__)
#include <malloc/malloc.h>
#else
#include <malloc.h>
#endif

JSValue js_print_to_console(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    int i;
    const char* str;
    size_t len;

    for (i = 0; i < argc; i++) {
        if (i != 0) fputc(' ', stdout);
        str = JS_ToCStringLen(ctx, &len, argv[i]);
        if (!str) return JS_EXCEPTION;
        fwrite(str, 1, len, stdout);
        JS_FreeCString(ctx, str);
    }
    fputc('\n', stdout);
    return JS_UNDEFINED;
}

void init_c_hooks(JSContext* ctx) {
    JSValue global_obj = JS_GetGlobalObject(ctx);
    JSValue console_obj = JS_NewObject(ctx);

    JS_SetPropertyStr(ctx, console_obj, "log",
        JS_NewCFunction(ctx, js_print_to_console, "log", 1));
    JS_SetPropertyStr(ctx, global_obj, "console", console_obj);

    JS_FreeValue(ctx, global_obj);    
}   

void dump_value_to_stream(JSContext* ctx, FILE* stream, JSValueConst val) {
    const char* strval = JS_ToCString(ctx, val);
    if (strval) {
        fprintf(stderr, "%s\n", strval);
        JS_FreeCString(ctx, strval);
    } else {
        fprintf(stderr, "[exception]\n");
    }
}


static int eval_buf(JSContext *ctx, const char *buf, int buf_len,
                    const char *filename, int eval_flags)
{
    JSValue val;
    int ret;

    if ((eval_flags & JS_EVAL_TYPE_MASK) == JS_EVAL_TYPE_MODULE) {
        /* for the modules, we compile then run to be able to set
           import.meta */
        val = JS_Eval(ctx, buf, buf_len, filename,
                      eval_flags | JS_EVAL_FLAG_COMPILE_ONLY);
        if (!JS_IsException(val)) {
            js_module_set_import_meta(ctx, val, TRUE, TRUE);
            val = JS_EvalFunction(ctx, val);
        }
        val = js_std_await(ctx, val);
    } else {
        val = JS_Eval(ctx, buf, buf_len, filename, eval_flags);
    }
    if (JS_IsException(val)) {
        js_std_dump_error(ctx);
        ret = -1;
    } else {
        ret = 0;
    }
    JS_FreeValue(ctx, val);
    return ret;
}

#include <stdio.h>
#include <string.h>

int has_suffix(const char *str, const char *suffix) {
    if (!str || !suffix) {
        return 0; // Retourne 0 si l'une des chaînes est NULL
    }

    size_t len_str = strlen(str);
    size_t len_suffix = strlen(suffix);

    // Vérifie si la longueur de suffixe est plus grande que celle de str
    if (len_suffix > len_str) {
        return 0;
    }

    // Compare la fin de str avec suffix
    return strcmp(str + len_str - len_suffix, suffix) == 0;
}


static int eval_file(JSContext *ctx, const char *filename, int module)
{
    uint8_t *buf;
    int ret, eval_flags;
    size_t buf_len;

    buf = js_load_file(ctx, &buf_len, filename);
    if (!buf) {
        perror(filename);
        exit(1);
    }

    if (module < 0) {
        module = (has_suffix(filename, ".mjs") ||
                  JS_DetectModule((const char *)buf, buf_len));
    }
    if (module)
        eval_flags = JS_EVAL_TYPE_MODULE;
    else
        eval_flags = JS_EVAL_TYPE_GLOBAL;
    ret = eval_buf(ctx, reinterpret_cast<const char *>(buf), buf_len, filename, eval_flags);
    js_free(ctx, buf);
    return ret;
}

#include <time.h>
#include <unistd.h>

// Simulate a simple setTimeout using sleep
static JSValue js_set_timeout(JSContext *ctx, JSValueConst this_val,
                              int argc, JSValueConst *argv) {
    if (argc != 2) {
        return JS_ThrowTypeError(ctx, "Expected 2 arguments");
    }

    if (!JS_IsFunction(ctx, argv[0])) {
        return JS_ThrowTypeError(ctx, "First argument must be a function");
    }

    int timeout;
    if (JS_ToInt32(ctx, &timeout, argv[1])) {
        return JS_ThrowTypeError(ctx, "Second argument must be a number");
    }

    // Sleep for the duration of the timeout in milliseconds
    usleep(timeout * 1000);

    // Call the provided function after the timeout
    JSValue result = JS_Call(ctx, argv[0], JS_UNDEFINED, 0, NULL);
    
    return result;
}



// Initialize the global 'self' and bind setTimeout
void init_global_self(JSContext *ctx) {
    // Create a new object 'self'
    JSValue global_self = JS_NewObject(ctx);

    // Bind the setTimeout function to 'self'
    JS_SetPropertyStr(ctx, global_self, "setTimeout",
                      JS_NewCFunction(ctx, js_set_timeout, "setTimeout", 2));

    // Bind 'self' to the global object
    JS_SetPropertyStr(ctx, JS_GetGlobalObject(ctx), "self", global_self);
}




// Structure pour stocker la réponse HTTP et l'état de la promesse
struct fetch_data {
    char *response;
    size_t size;
    JSContext *ctx;
    JSValue resolve;
    JSValue reject;
};

/*
// Callback pour traiter les données reçues par CivetWeb
static int fetch_callback(struct mg_connection *conn,  const mg_response_info *info, struct fetch_data *mem)
{
    if (info->status_code != 200) {
        // En cas d'erreur HTTP, rejeter la promesse
        JSValue error = JS_NewString(mem->ctx, "Erreur lors de la requête HTTP");
        JS_Call(mem->ctx, mem->reject, JS_UNDEFINED, 1, &error);
        JS_FreeValue(mem->ctx, error);
        return 0;
    }

    // Allouer la mémoire pour la réponse
    char *ptr = static_cast<char *>(realloc(mem->response, mem->size + body_len + 1));
    if (ptr == NULL) {
        printf("Pas assez de mémoire pour la réponse\n");
        return 0;
    }

    mem->response = ptr;
    memcpy(&(mem->response[mem->size]), info-body, body_len);
    mem->size += body_len;
    mem->response[mem->size] = '\0'; // Terminer la chaîne

    // Créer une chaîne JavaScript pour la réponse
    JSValue js_response = JS_NewString(mem->ctx, mem->response);

    // Résoudre la promesse avec la réponse
    JS_Call(mem->ctx, mem->resolve, JS_UNDEFINED, 1, &js_response);

    // Libérer les ressources
    JS_FreeValue(mem->ctx, js_response);

    return 1; // Tout s'est bien passé
}
*/

int http_request(const char* host)
{
    /* Connect client */
	char errbuf[256] = {0};
	struct mg_client_options opt = {0};
	opt.host = host;       /* Host name from command line */
	opt.port = 443;           /* Default HTTPS port */
	opt.client_cert = NULL;   /* Client certificate, if required */
	opt.server_cert = NULL;   /* Server certificate to verify */
	opt.host_name = opt.host; /* Host name for SNI */
	struct mg_connection *cli =
	    mg_connect_client_secure(&opt, errbuf, sizeof(errbuf));

	/* Check return value: */
	if (cli == NULL) {
		fprintf(stderr, "Cannot connect client: %s\n", errbuf);
		return EXIT_FAILURE;
	}

	printf("cli: %p\n", cli);

	mg_printf(cli, "GET / HTTP/1.1\r\n");
	mg_printf(cli, "Host: %s\r\n", opt.host);
	mg_printf(cli, "Connection: close\r\n\r\n");

	int ret = mg_get_response(cli, errbuf, sizeof(errbuf), 10000);
	if (ret < 0) {
		fprintf(stderr, "Download failed: %s\n", errbuf);
		mg_close_connection(cli);
		return EXIT_FAILURE;
	}

	const struct mg_response_info *ri = mg_get_response_info(cli);
	if (ri == NULL) {
		fprintf(stderr, "mg_response_info failed\n");
		mg_close_connection(cli);
		return EXIT_FAILURE;
	}

	printf("Status: %i %s\n", ri->status_code, ri->status_text);
	printf("HTTP Version: %s\n", ri->http_version);
	printf("Content-Length: %lli\n", ri->content_length);
	printf("Headers:\n");
	int is_chunked = 0;
	for (int i = 0; i < ri->num_headers; i++) {
		printf("  %s: %s\n",
		       ri->http_headers[i].name,
		       ri->http_headers[i].value);
		if (!strcasecmp(ri->http_headers[i].name, "Transfer-Encoding")
		    && !strcasecmp(ri->http_headers[i].value, "chunked")) {
			is_chunked = 1;
		}
	}

	long long cont = ri->content_length;
	if (cont > 0) {
		/* Read regular content */
		printf("Content:\n");
		while (cont > 0) {
			char buf[1024];
			int ret = mg_read(cli, buf, sizeof(buf));
			if (ret <= 0) {
				printf("read error\n");
				break;
			}
			cont -= ret;
			fwrite(buf, 1, ret, stdout);
		}
	} else {
		/* Read chunked content (or content without content length) */
		char buf[1024];
		for (;;) {
			int ret = mg_read(cli, buf, sizeof(buf));
			if (ret <= 0)
				break;
			fwrite(buf, 1, ret, stdout);
		}
	}

	mg_close_connection(cli);
    return 0;
}

// Fonction fetch en C utilisant CivetWeb et retournant une Promise
static JSValue js_fetch(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if (argc < 1 || argc > 2) {
        return JS_ThrowTypeError(ctx, "fetch requiert 1 ou 2 arguments (URL, options)");
    }

    struct fetch_data *chunk = static_cast<struct fetch_data *>(malloc(sizeof(struct fetch_data)));
    chunk->response = static_cast<char *>(malloc(1));
    chunk->size = 0;
    chunk->ctx = ctx;

    JSValue promise = JS_NewPromiseCapability(ctx, &chunk->resolve);
/*
    // Récupérer l'URL
    const char *url = JS_ToCString(ctx, argv[0]);
    if (!url) {
        return JS_ThrowTypeError(ctx, "L'argument doit être une URL valide");
    }

    // Initialisation des paramètres par défaut
    const char *method = "GET";
    const char *body = NULL;
    const char *headers = "";

    // Si un objet d'options est fourni, récupérer les options
    if (argc == 2 && JS_IsObject(argv[1])) {
        JSValue methodVal = JS_GetPropertyStr(ctx, argv[1], "method");
        if (JS_IsString(methodVal)) {
            method = JS_ToCString(ctx, methodVal);
            JS_FreeValue(ctx, methodVal);
        }

        JSValue bodyVal = JS_GetPropertyStr(ctx, argv[1], "body");
        if (JS_IsString(bodyVal)) {
            body = JS_ToCString(ctx, bodyVal);
            JS_FreeValue(ctx, bodyVal);
        }

        JSValue headersVal = JS_GetPropertyStr(ctx, argv[1], "headers");
        if (JS_IsString(headersVal)) {
            headers = JS_ToCString(ctx, headersVal);
            JS_FreeValue(ctx, headersVal);
        }
    }

    // Variables pour gérer les erreurs et la réponse
    char ebuf[100];
    struct fetch_data *chunk = static_cast<struct fetch_data *>(malloc(sizeof(struct fetch_data)));
    chunk->response = static_cast<char *>(malloc(1));
    chunk->size = 0;
    chunk->ctx = ctx;

    // Extraire l'hôte et le chemin de l'URL (simplifié pour cet exemple)
    const char *host = "example.com";  // Utiliser un vrai parseur d'URL pour extraire l'hôte
    const char *path = "/";            // Utiliser un vrai parseur pour le chemin

    // Création de la promesse JavaScript
    JSValue promise = JS_NewPromiseCapability(ctx, &chunk->resolve);//, &chunk->reject);

    // Construire la requête HTTP
    const char *format = body ? "%s %s HTTP/1.0\r\nHost: %s\r\n%s\r\nContent-Length: %d\r\n\r\n%s"
                              : "%s %s HTTP/1.0\r\nHost: %s\r\n%s\r\n\r\n";
    struct mg_connection *conn;

    if (body) {
        conn = mg_download(host, 80, 0, ebuf, sizeof(ebuf), format, method, path, host, headers, strlen(body), body);
    } else {
        conn = mg_download(host, 80, 0, ebuf, sizeof(ebuf), format, method, path, host, headers);
    }

    if (conn == NULL) {
        // Si la connexion échoue, rejeter la promesse
        JSValue error = JS_NewString(ctx, ebuf);
        JS_Call(ctx, chunk->reject, JS_UNDEFINED, 1, &error);
        JS_FreeValue(ctx, error);
        JS_FreeCString(ctx, url);
        free(chunk->response);
        free(chunk);
        return promise;
    }

    // Lire la réponse HTTP
    const mg_response_info *info = mg_get_response_info(conn); 
    if (info && info->status_code == 200) {
        fetch_callback(conn, info, chunk);
    } else {
        // En cas d'échec ou de réponse non-200, rejeter la promesse
        JSValue error = JS_NewString(ctx, "Erreur HTTP ou statut non 200");
        JS_Call(ctx, chunk->reject, JS_UNDEFINED, 1, &error);
        JS_FreeValue(ctx, error);
    }

    mg_close_connection(conn);
  

    // Libérer les ressources
    JS_FreeCString(ctx, url);
    free(chunk->response);
    free(chunk);
  */
    return promise; // Retourne la promesse
}

// Initialisation de fetch dans le contexte global de QuickJS
void init_global_fetch(JSContext *ctx) {
    // Bind la fonction fetch à l'objet global
    JS_SetPropertyStr(ctx, JS_GetGlobalObject(ctx), "fetch",
                      JS_NewCFunction(ctx, js_fetch, "fetch", 2));
}


// Structure pour stocker les en-têtes HTTP
typedef struct {
    JSContext *ctx;
    JSValue headers;  // Un objet JavaScript qui stocke les en-têtes sous forme clé-valeur
} Headers;

// Méthode pour obtenir un en-tête
static JSValue js_headers_get(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if (argc != 1 || !JS_IsString(argv[0])) {
        return JS_ThrowTypeError(ctx, "Headers.get requiert 1 argument (clé string)");
    }

    const char *key = JS_ToCString(ctx, argv[0]);
    if (!key) {
        return JS_ThrowTypeError(ctx, "Clé invalide");
    }

    JSValue headers = JS_GetPropertyStr(ctx, this_val, "headers");
    JSValue val = JS_GetPropertyStr(ctx, headers, key);
    JS_FreeCString(ctx, key);

    if (JS_IsUndefined(val)) {
        return JS_UNDEFINED;  // Retourne `undefined` si l'en-tête n'existe pas
    }
    
    return val;  // Retourne la valeur de l'en-tête
}

// Méthode pour définir un en-tête
static JSValue js_headers_set(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if (argc != 2 || !JS_IsString(argv[0]) || !JS_IsString(argv[1])) {
        return JS_ThrowTypeError(ctx, "Headers.set requiert 2 arguments (clé, valeur strings)");
    }

    const char *key = JS_ToCString(ctx, argv[0]);
    const char *value = JS_ToCString(ctx, argv[1]);
    if (!key || !value) {
        return JS_ThrowTypeError(ctx, "Clé ou valeur invalide");
    }

    JSValue headers = JS_GetPropertyStr(ctx, this_val, "headers");
    JS_SetPropertyStr(ctx, headers, key, JS_NewString(ctx, value));

    JS_FreeCString(ctx, key);
    JS_FreeCString(ctx, value);

    return JS_UNDEFINED;
}

// Méthode pour vérifier si un en-tête existe
static JSValue js_headers_has(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if (argc != 1 || !JS_IsString(argv[0])) {
        return JS_ThrowTypeError(ctx, "Headers.has requiert 1 argument (clé string)");
    }

    const char *key = JS_ToCString(ctx, argv[0]);
    if (!key) {
        return JS_ThrowTypeError(ctx, "Clé invalide");
    }

    JSValue headers = JS_GetPropertyStr(ctx, this_val, "headers");
    JSValue val = JS_GetPropertyStr(ctx, headers, key);
    JS_FreeCString(ctx, key);

    return JS_NewBool(ctx, !JS_IsUndefined(val));  // Retourne vrai si l'en-tête existe
}

// Méthode pour supprimer un en-tête
static JSValue js_headers_delete(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if (argc != 1 || !JS_IsString(argv[0])) {
        return JS_ThrowTypeError(ctx, "Headers.delete requiert 1 argument (clé string)");
    }

    const char *key = JS_ToCString(ctx, argv[0]);
    if (!key) {
        return JS_ThrowTypeError(ctx, "Clé invalide");
    }

    JSValue headers = JS_GetPropertyStr(ctx, this_val, "headers");

    JSValue val = JS_GetPropertyStr(ctx, headers, key);
    JSAtom atom = JS_ValueToAtom(ctx, val);
    JS_DeleteProperty(ctx, headers, atom, JS_PROP_THROW);

    JS_FreeCString(ctx, key);

    return JS_UNDEFINED;
}

// Constructeur de la classe Headers
static JSValue js_headers_constructor(JSContext *ctx, JSValueConst new_target, int argc, JSValueConst *argv) {
    JSValue obj = JS_NewObjectClass(ctx, JS_GetClassID(new_target));

    // Créer un objet interne pour stocker les en-têtes
    JSValue headers_obj = JS_NewObject(ctx);
    JS_DefinePropertyValueStr(ctx, obj, "headers", headers_obj, JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);

    if (argc == 1 && JS_IsObject(argv[0])) {
        // Si un objet ou un tableau d'en-têtes est passé au constructeur
        JSValue iter_func = JS_GetPropertyStr(ctx, argv[0], "entries");
        if (!JS_IsUndefined(iter_func)) {
            // Récupérer l'itérateur symbolique avec la chaîne "Symbol.iterator"
            JSValue symbol_iterator = JS_GetPropertyStr(ctx, argv[0], "Symbol.iterator");
            
            JSValue iter = JS_Call(ctx, symbol_iterator, argv[0], 0, NULL);
            JS_FreeValue(ctx, symbol_iterator);

            JSValue next_method = JS_GetPropertyStr(ctx, iter, "next");
            JSValue result;
            while (1) {
                result = JS_Call(ctx, next_method, iter, 0, NULL);
                JSValue done = JS_GetPropertyStr(ctx, result, "done");
                if (JS_ToBool(ctx, done)) {
                    JS_FreeValue(ctx, done);
                    JS_FreeValue(ctx, result);
                    break;
                }
                JSValue value = JS_GetPropertyStr(ctx, result, "value");
                JSValue key = JS_GetPropertyUint32(ctx, value, 0);
                JSValue val = JS_GetPropertyUint32(ctx, value, 1);
                const char *key_str = JS_ToCString(ctx, key);
                const char *val_str = JS_ToCString(ctx, val);
                JS_SetPropertyStr(ctx, headers_obj, key_str, JS_NewString(ctx, val_str));
                JS_FreeCString(ctx, key_str);
                JS_FreeCString(ctx, val_str);
                JS_FreeValue(ctx, done);
                JS_FreeValue(ctx, value);
                JS_FreeValue(ctx, key);
                JS_FreeValue(ctx, val);
                JS_FreeValue(ctx, result);
            }
        }
    }

    return obj;
}

static const JSCFunctionListEntry headersFunctionList[] = {
        JS_CFUNC_DEF("get", 1, js_headers_get),
        JS_CFUNC_DEF("set", 2, js_headers_set),
        JS_CFUNC_DEF("has", 1, js_headers_has),
        JS_CFUNC_DEF("delete", 1, js_headers_delete),
    };

// Enregistrement de la classe Headers
static int js_headers_init(JSContext *ctx) {
    JSClassDef class_def = {
        "Headers",  // Nom de la classe
        .finalizer = NULL
    };

    JSValue proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, proto, headersFunctionList, 4);
    
    JSValue constructor = JS_NewCFunction2(ctx, js_headers_constructor, "Headers", 1, JS_CFUNC_constructor, 0);
    JS_SetConstructor(ctx, constructor, proto);

    // Lier le constructeur au contexte global
    JS_SetPropertyStr(ctx, JS_GetGlobalObject(ctx), "Headers", constructor);

    return 0;
}

/* also used to initialize the worker context */
static JSContext *JS_NewCustomContext(JSRuntime *rt)
{
    JSContext *ctx;
    ctx = JS_NewContext(rt);
    if (!ctx)
        return NULL;
#ifdef CONFIG_BIGNUM
    if (bignum_ext) {
        JS_AddIntrinsicBigFloat(ctx);
        JS_AddIntrinsicBigDecimal(ctx);
        JS_AddIntrinsicOperators(ctx);
        JS_EnableBignumExt(ctx, TRUE);
    }
#endif
    /* system modules */
    js_init_module_std(ctx, "std");
    js_init_module_os(ctx, "os");
    return ctx;
}

// Fonction pour lire le contenu d'un fichier JavaScript
char* read_file(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        perror("Cannot open file");
        return NULL;
    }
    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    char* content = static_cast<char*>(malloc(length + 1));
    if (!content) {
        perror("Memory allocation failed");
        fclose(file);
        return NULL;
    }

    fread(content, 1, length, file);
    content[length] = '\0';
    fclose(file);
    return content;
}

// Simuler require() pour charger un module
JSValue js_require(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if (argc < 1) {
        return JS_EXCEPTION;
    }

    const char *module_name = JS_ToCString(ctx, argv[0]);
    if (!module_name) {
        return JS_EXCEPTION;
    }

    // Ajouter l'extension .js pour le fichier
    char file_name[256];
    snprintf(file_name, sizeof(file_name), "%s.js", module_name);

    // Lire le contenu du fichier
    char* code = read_file(file_name);
    if (!code) {
        JS_FreeCString(ctx, module_name);
        return JS_EXCEPTION;
    }

    // Créer l'environnement du module avec `module` et `exports`
    const char* wrapper_prefix = "(function(require, module, exports) {";
    const char* wrapper_suffix = "})";
    size_t wrapped_code_len = strlen(wrapper_prefix) + strlen(code) + strlen(wrapper_suffix) + 1;
    char* wrapped_code = static_cast<char*>(malloc(wrapped_code_len));

    snprintf(wrapped_code, wrapped_code_len, "%s%s%s", wrapper_prefix, code, wrapper_suffix);
    free(code);

    // Créer les objets module et exports
    JSValue module = JS_NewObject(ctx);
    JSValue exports = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, module, "exports", exports);

    // Compiler et exécuter le module JavaScript
    JSValue result = JS_Eval(ctx, wrapped_code, strlen(wrapped_code), file_name, JS_EVAL_TYPE_GLOBAL);
    free(wrapped_code);

    if (JS_IsException(result)) {
        JS_FreeValue(ctx, result);
        JS_FreeCString(ctx, module_name);
        return JS_EXCEPTION;
    }

    // Appeler le wrapper fonctionnel du module
    JSValue args[3] = { JS_UNDEFINED, module, exports };
    JSValue require_func = JS_NewCFunction(ctx, js_require, "require", 1);
    args[0] = require_func;

    JSValue func = JS_Call(ctx, result, JS_UNDEFINED, 3, args);
    JS_FreeValue(ctx, result);
    JS_FreeValue(ctx, require_func);

    if (JS_IsException(func)) {
        JS_FreeCString(ctx, module_name);
        return JS_EXCEPTION;
    }

    JS_FreeValue(ctx, func);

    // Retourner module.exports
    JSValue module_exports = JS_GetPropertyStr(ctx, module, "exports");
    JS_FreeValue(ctx, module);
    JS_FreeCString(ctx, module_name);
    return module_exports;
}


int main(int argc, const char* argv[]) {
    JSRuntime* jsrt;
    JSContext* jsctx;

    JSMemoryUsage stats;
    JSValue result;
    const char* script =
        "import * as pdb from './pouchdb-9.0.0.js';\n" 
        "console.log('Hello');\n"      
    ;

     jsrt = JS_NewRuntime();
    js_std_set_worker_new_context_func(JS_NewCustomContext);
    js_std_init_handlers(jsrt);
    jsctx = JS_NewCustomContext(jsrt);

   
    // jsctx = JS_NewContext(jsrt);
    if (!jsctx) {
        fprintf(stderr, "Failed to create a new JS context\n");
        return 1;
    }

     /* loader for ES6 modules */
    JS_SetModuleLoaderFunc(jsrt, NULL, js_module_loader, NULL);


    init_c_hooks(jsctx);
    

// Initialize global self and setTimeout
    init_global_self(jsctx);

    init_global_fetch(jsctx);

    js_headers_init(jsctx);

     JSValue global_obj = JS_GetGlobalObject(jsctx);
    JS_SetPropertyStr(jsctx, global_obj, "require", JS_NewCFunction(jsctx, js_require, "require", 1));
    JS_FreeValue(jsctx, global_obj);

    int res = eval_file(jsctx, argv[1], 1);
    
   // JS_ComputeMemoryUsage(jsrt, &stats);
   // JS_DumpMemoryUsage(stdout, &stats, jsrt);

    js_std_free_handlers(jsrt);
    JS_FreeContext(jsctx);
    JS_FreeRuntime(jsrt);

    return 0;
}