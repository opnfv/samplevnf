/*******************************************************************************
 * Copyright (c) 2017 Kumar Rishabh and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License, Version 2.0
 * which accompanies this distribution, and is available at
 * http://www.apache.org/licenses/LICENSE-2.0
 *******************************************************************************/

var express = require('express');
var router = express.Router();
var async = require('async');


var renderer = function(res, err, results) {
    console.log(results);
    res.render('project_profile', { title: 'Express', json: results });
}

var renderer_post = function(res, err, results) {
    console.log(results);
    res.end(JSON.stringify(results));
}

var get_tags = function(result, callback) {
    db_pool.getConnection(function(err, connection) {
        sql_query = 'select tag_name from tag where tag_id in (select tag_id from vnf_tags where vnf_id = ' + result['vnf_id'] + ') limit 5';
        // TODO find why it works and not above
        connection.query(sql_query, function (error, results, fields) {
            console.log(results);
            result['tags'] = results;
            connection.release();
            if (error) {
                result['tags'] = {};
                //throw error;
            } else {
                result['tags'] = results;
            }
            callback(null, result);
            //if (error) throw error;
        });
    });
}


var get_images = function(result, callback) {
    db_pool.getConnection(function(err, connection) {
        sql_query = 'select photo_url from photo where photo_id = ' + result['photo_id'];
        // TODO find why it works here and not when declared outside the method
        console.log(sql_query);
        connection.query(sql_query, function (error, results, fields) {
            console.log(results[0].photo_url);
            //result['photo_url'] = results[0].photo_url;
            connection.release();
            if (error) {
                result['photo_url'] = false;
                //throw error;
            } else {
                result['photo_url'] = results[0].photo_url;
            }
            callback(null, result);
            //if (error) throw error;
        });
    });
}

var sql_data = function(vnf_id, renderer, res) {
    db_pool.getConnection(function(err, connection) {
        sql_query = 'select * from vnf where vnf_id = '+ vnf_id;
        connection.query(sql_query, function (error, results, fields) {
            console.log(results);
            connection.release();
            if (error) {
                console.log('connection error occurred');
            } else {
                async.map(results, get_images, function(error, results) {
                    async.map(results, get_tags, renderer.bind(null, res));
                });
            }   
            //connection.release();
            //if (error) throw error;
        });
    });

}

router.get('/', function(req, res) {
    console.log(typeof(req.param('vnf_id')));
    var vnf_id = req.param('vnf_id');

    if(vnf_id) {
        //tags = tags.toLowerCase().split(/[ ,]+/);
        //console.log(tags);
        sql_data(vnf_id, renderer, res);
    } else {
        res.render('project_profile', { title: 'Express', json: false});
    }
});

router.post('/', function(req, res) {
    console.log(typeof(req.param('vnf_id')));
    var vnf_id = req.param('vnf_id');

    if(vnf_id) {
        //tags = tags.toLowerCase().split(/[ ,]+/);
        //console.log(tags);
        sql_data(vnf_id, renderer_post, res);
    } else {
        res.end('{"error" : "VNF Project could not get loaded", "status" : 500}');

    }
});


module.exports = router;
