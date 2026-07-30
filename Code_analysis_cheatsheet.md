# Code analysis and whitebox pentesting cheatsheet

## Steps

 1. Code review and analysis
 2. Local testing / debugging
 3. Proof of concept creation 
 4. Patch / Remidiation suggestion

## Prioritisation 

It would take to much time to test large codebase, thatfor we prioritize certain functions or parts of the code:

 - Functions which handle authentication can lead to an authentication bypass
 - Functions which interact with the OS or run system commands may lead to command injection / RCE.
 - Functions used to exchange data with the DB may lead to SQLi / NoSQLi.
 - etc.

This can be done by:

 - Searching for certain function-names and other keywords like `eval`, `system`, `exec`, `mysqli_query`, `password_hash`, ...
 - Identifying them from the design-documentation of the application.
 - Using a debugger to see what functions are called in speciffic situations.

Then use the **Impact X Probabbility** matrix to prioritize the identified functions of interest:

| Impact/Likelyhood | Low        | Medium       | High        |
|-------------------|------------|--------------|-------------|
| **Low**           | Lowest     | Low          | Medium      |
| **Medium**        | Low        | Medium       | High        |
| **High**          | Medium     | High         | Highest     |

### Identifying parameters and endpoints in sourcecode

 - `java -jar attack-surface-detector-cli-1.3.5.jar /path/to/sourcecode/`  
   https://github.com/secdec/attack-surface-detector-cli/releases

---

## Code- and command injection functions

**JavaScript / NodeJS**

 - eval
 - Function
 - setInterval
 - setTimeout
 - constructor.constructor
 - child_process.exec (need callback function)
 - child_process.spawn (need callback function)
 - child_process.execSync
 - child_process.spawnSync
 - 

**Python**

 - eval
 - exec
 - subprocess.open
 - subprocess.run				
 - os.system
 - os.popen

**PHP**

 - eval
 - exec
 - proc_open
 - popen
 - shell_exec
 - passthru
 - system

**C/C++**

 - execlp
 - execvp
 - ShellExecute
 - system
 - popen

**C#**

 - System.Diagnostics.Process.Start

**Java**

 - Runtime.getRuntime().exec

### Code injection in JavaScript after a `throw()`-function

 - `throw()` - ends execution and give back an error 
   - `;` can't be used to execute code after - execution will be terminalted after the function and the code after `;` would be seen as code in a new line, that is never reached
   - `+` allows the concatinate the exeution of code in that case: `throw(...) + console.log('pwned')` 

### Command-execution without loading the NodeJS module

```javascript
global.process.mainModule.constructor._load('child_process').execSync('whoami').toString()

require("child_process").execSync("whoami").toString()

```



---