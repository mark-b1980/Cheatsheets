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

