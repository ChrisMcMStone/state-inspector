const http = require('http');

console.log(process.argv);
console.log(process.argv[2]);

var dot_dir = process.argv[2];

if (dot_dir[dot_dir.length-1] != '/') dot_dir = dot_dir + '/';

console.log(dot_dir);

var url = require('url');  
var fs = require('fs');  
var server = http.createServer(function(request, response) {  
    var path = url.parse(request.url).pathname;  
    if (path.includes("js")) {
        fs.readFile(__dirname + path, function(error, data) {  
            if (error) {  
                response.writeHead(404);  
                response.write(error);  
                response.end();  
            } else {  
                console.log("sending  " + path);
                response.writeHead(200, {  
                    'Content-Type': 'text/javascript'  
                });  
                response.write(data);  
                response.end();  
            }  
        });  
    } else {
        switch (path) {  
            case '/':  
            case '/index.html':  
                fs.readFile(__dirname + path, function(error, data) {  
                    if (error) {  
                        response.writeHead(404);  
                        response.write(error);  
                        response.end();  
                    } else {  
                        response.writeHead(200, {  
                            'Content-Type': 'text/html'  
                        });  
                        response.write(data);  
                        response.end();  
                    }  
                });  
                break;  
            default:  
                var dot = null;
                try { 
                    dot = fs.readFileSync(dot_dir+path, 'utf8');
                } catch {
                    dot = '';
                }
                response.writeHead(200, {  
                    'Content-Type': 'text/html'  
                });  
                response.write(dot);
                response.end();
                break;  
        }  
    }
});  
server.listen(3000); 
