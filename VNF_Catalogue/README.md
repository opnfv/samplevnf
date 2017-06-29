#VNF_Catalogue Nodejs + Jade + MySql server


## Quickstart

First install docker and docker-compose. This multicontainer app uses
docker-compose to organize the vnf_catalogue web_app

The use
    ```docker-compose up```

set time zone(optional)
        Set same timezone in both nodejs server and mysql server. Something
        similar to below can be used:
        ``` SET GLOBAL time_zone = '+00:00'; ```


The server would be accessible at ```ip_address:3000```
