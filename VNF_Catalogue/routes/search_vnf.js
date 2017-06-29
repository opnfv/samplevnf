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

/* Post Controller for Search Vnf autocomplete form */
router.get('/', function(req, res) {
    tag_partial = req.param('key');
    db_pool.getConnection(function(err, connection) {

        sql_query = 'select vnf_name from vnf where vnf_name like "%'+ tag_partial + '%" limit 5';
        // TODO find why it works and not above
        connection.query(sql_query, function (error, results, fields) {
            console.log(results);
            if(results == null) {
                connection.release();
                res.end(JSON.stringify({}));
            } else {
                var data=[];
                for(i = 0; i < results.length; i++) {
                    data.push(results[i].vnf_name.replace(/\r?\n|\r/g, ''));
                }
                console.log(results);
                connection.release();
                res.end(JSON.stringify(results));
            }
            //if (error) throw error;
        });
    });
});

module.exports = router;
