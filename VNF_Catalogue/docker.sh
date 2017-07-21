sudo chmod -R 777 persistent_data
docker rmi $(docker images -f dangling=true -q)
docker rm $(docker ps -a -f status=exited -q)
docker volume rm $(docker volume ls -f dangling=true -q)
docker-compose stop
docker-compose rm -f
docker-compose build
docker-compose up
