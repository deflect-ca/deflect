echo "GET"
curl -X GET http://localhost:8080/GET?param=hello
echo "\nOPTIONS"
curl -X OPTIONS http://localhost:8080/OPTIONS?param=hello
echo "\nHEAD"
curl -I http://localhost:8080/GET?param=hello

echo "POST"
curl -X POST -d "form=some_data" http://localhost:8080/POST?param=hello
echo "\nPOST RAW"
curl -X POST -H "Content-Type: application/json" -d '{"key1":"value"}' http://localhost:8080/POST_RAW?param=hello

echo "\n\nPUT"
curl -X PUT -d "form=some_data" http://localhost:8080/PUT?param=hello
echo "\nPUT RAW"
curl -X PUT -H "Content-Type: application/json" -d '{"key1":"value"}' http://localhost:8080/PUT_RAW?param=hello

echo "\n\nPATCH"
curl -X PATCH -d "form=some_data" http://localhost:8080/PATCH?param=hello
echo "\nPATCH RAW"
curl -X PATCH -H "Content-Type: application/json" -d '{"key1":"value"}' http://localhost:8080/PATCH_RAW?param=hello

echo "\n\nDELETE"
curl -X DELETE http://localhost:8080/DELETE?param=hello

echo "\n\nUPLOAD"
curl -X POST http://localhost:8080/upload?param=hello \
  -F "file=@./deflect.png" \
  -H "Content-Type: multipart/form-data"
