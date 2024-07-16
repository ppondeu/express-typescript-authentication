# Getting Started with Express + Typescript

###### follow these step to install dependency
    1. npm init -y

    2. mkdir src

    3. cd src & touch index.ts

    4. npm i express

    5. npm i -D typescript @types/express

    6. npx tsc --init

    7. in tsconfig.json uncomment and set "rootDir": "./src" and uncomment and set "outDir": "./dist" and uncomment noImplicitAny, strictNullChecks, strictFunctionTypes

    8. npx tsc --build and then you will got ./dist folder that have index.js inside

    9. now let try to run node ./dist/index.js

    10. add the script into package.json 
        "scripts": {
            "test": "echo \"Error: no test specified\" && exit 1",
            "build": "tsc --build",
            "start": "node ./dist/index.js"
        },
    
    11. npm i -D nodemon

    12. modify the script in package.json like this
        "scripts": {
            "test": "echo \"Error: no test specified\" && exit 1",
            "build": "tsc --build",
            "start": "node ./dist/index.js",
            "start:dev": "nodemon ./src/index.ts"
        },
    
    13. npm i -D ts-node