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

/* Post Controller for Tag autocomplete form */
router.get('/', function(req, res) {
    tag_partial = req.param('key');
    db_pool.getConnection(function(err, connection) {

        sql_query = 'select tag_name from tag where tag_name like "%'+ tag_partial + '%" and is_vnf_name = false limit 5';
        // TODO find why it works and not above
        console.log(sql_query);
        connection.query(sql_query, function (error, results, fields) {
            console.log(results);

            if(results == null) {
                connection.release();
                res.end(JSON.stringify({}));
            } else {
                var data=[];
                for(i = 0; i < results.length; i++) {
                    data.push(results[i].tag_name.replace(/\r?\n|\r/g, ''));
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
