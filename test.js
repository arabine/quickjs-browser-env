
/*
// Initialize an empty module object
var module = {};

// Default namespace is the top-level (global) object
var exports = Function('return this')();

Object.defineProperties(module, {
    'namespace': {
      // Change the namespace to another object
      set: function (obj) {
        exports = obj;
      }
    },
    'exports': {
      // Extend the namespace object with the object that's passed
      set: function (obj) {
        for (var prop in obj) {
          // Don't set properties inherited from the prototype
          if (obj.hasOwnProperty(prop)) {
            exports[prop] = obj[prop];
          }
        }
      },
      // Return the namespace
      get: function () {
        return exports;
      }
    }
});
*/

const window = {};
const document = {};

globalThis.window = window;
globalThis.document = document;

// import * as PouchDB from './pouchdb-9.0.0.js'

let PouchDB = require('./pouchdb-9.0.0.js')

// import PouchDB from "./pouchdb-es.js";

console.log('Hello: ' + typeof(PouchDB));

  console.log(JSON.stringify(PouchDB, null, 2)); 

const db = new PouchDB('todos');
// const remoteCouch = false;
