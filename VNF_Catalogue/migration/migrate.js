/*******************************************************************************
 * Copyright (c) 2017 Kumar Rishabh(penguinRaider) and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License, Version 2.0
 * which accompanies this distribution, and is available at
 * http://www.apache.org/licenses/LICENSE-2.0
 *******************************************************************************/

var knex = require('knex')({
    client: 'mysql',
    connection: {
        host     : process.env.DB_HOST,
        user     : process.env.DB_USER,
        password : process.env.DB_PASSWORD,
        database : process.env.DB_DATABASE,
        charset  : 'utf8'
    }
});
var Schema = require('./schema');
var sequence = require('when/sequence');
var _ = require('lodash');
var moment = require('moment');

function createTable(tableName) {
    return knex.schema.createTable(tableName, function (table) {
    var column;
    var columnKeys = _.keys(Schema[tableName]);
    _.each(columnKeys, function (key) {
        if (Schema[tableName][key].type === 'text' && Schema[tableName][key].hasOwnProperty('fieldtype')) {
        column = table[Schema[tableName][key].type](key, Schema[tableName][key].fieldtype);
        }
        else if (Schema[tableName][key].type === 'enum' && Schema[tableName][key].hasOwnProperty('values') && Schema[tableName][key].nullable === true) {
        console.log(Schema[tableName][key].values);
        column = table[Schema[tableName][key].type](key, Schema[tableName][key].values).nullable();
        }
        else if (Schema[tableName][key].type === 'enum' && Schema[tableName][key].hasOwnProperty('values')) {
        console.log(Schema[tableName][key].values);
        column = table[Schema[tableName][key].type](key, Schema[tableName][key].values).notNullable();
        }
        else if (Schema[tableName][key].type === 'string' && Schema[tableName][key].hasOwnProperty('maxlength')) {
        column = table[Schema[tableName][key].type](key, Schema[tableName][key].maxlength);
        }
        else {
        column = table[Schema[tableName][key].type](key);
        }
        if (Schema[tableName][key].hasOwnProperty('nullable') && Schema[tableName][key].nullable === true) {
        column.nullable();
        }
        else {
        column.notNullable();
        }
        if (Schema[tableName][key].hasOwnProperty('primary') && Schema[tableName][key].primary === true) {
        column.primary();
        }
        if (Schema[tableName][key].hasOwnProperty('unique') && Schema[tableName][key].unique) {
        column.unique();
        }
        if (Schema[tableName][key].hasOwnProperty('unsigned') && Schema[tableName][key].unsigned) {
        column.unsigned();
        }
        if (Schema[tableName][key].hasOwnProperty('references')) {
        column.references(Schema[tableName][key].references);
        }
        if (Schema[tableName][key].hasOwnProperty('defaultTo')) {
        column.defaultTo(Schema[tableName][key].defaultTo);
        }
    });
    });
}
function createTables () {
    var tables = [];
    var tableNames = _.keys(Schema);
    tables = _.map(tableNames, function (tableName) {
    return function () {
        return createTable(tableName);
    };
    });
    return sequence(tables);
}

function mysql_datetime() {
    return moment(new Date()).format('YYYY-MM-DD HH:mm:ss');
}

createTables()
.then(function() {
    console.log('Tables created!!');
    var current_time = mysql_datetime();
    console.log(current_time);

    knex.insert([{user_name: 'admin', password: 'admin', email_id: 'admin@opnfv.org', company: 'opnfv', introduction: 'hello world',
                created_at: current_time}]).into('user').then(function() {                                                           
                    process.exit(0)});;
})
.catch(function (error) {
    console.log('error creating the database perhaps it exists?(If yes congrats the persistance of mysql works :-D)');
    process.exit(0);
    //throw error;
});
