# QuickJS browser environment

QuickJS library to add minimal browser environment, first used to run PouchDB

# Project status

Work in progress.

| Javascript object | Polyfill in C | Implementation status | Unit test |
|---|---|---|---|
| self | C function | ✅ | ❌ |
| setTimeout | C function | ✅ | ❌ |
| fetch | CivetWeb | ❌ | ❌ |
| Headers | C function | ✅ | ❌ |
