import * as shell from 'shelljs';
shell.rm('-R', './dist/server');
shell.rm('-R', './dist/package.json');
shell.rm('-R', './dist/tsconfig.json');
