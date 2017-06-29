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
    res.render('index', { title: 'Express', json: results });
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

/* GET VNF_Catalogue Home Page. */
router.get('/', function(req, res) {
    db_pool.getConnection(function(err, connection) {
        sql_query = 'select * from vnf order by lines_of_code desc limit 8';
        // TODO find why it works and not above
        connection.query(sql_query, function (error, results, fields) {
            //console.log(results);
            connection.release();
            if (error) {
            	res.render('index', { title: 'Express', json: false});
            } else {
            	async.map(results, get_images, renderer.bind(null, res));
            	//res.render('index', { title: 'Express', json: results});    
            }
        });
    });
});

module.exports = router;
