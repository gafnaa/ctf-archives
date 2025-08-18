docker build --tag=magic_library .
docker run -p 1337:80 --rm --name=magic_library -it magic_library 
