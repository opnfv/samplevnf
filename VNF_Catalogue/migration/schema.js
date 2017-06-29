/*******************************************************************************
 * Copyright (c) 2017 Kumar Rishabh(penguinRaider) and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License, Version 2.0
 * which accompanies this distribution, and is available at
 * http://www.apache.org/licenses/LICENSE-2.0
 *******************************************************************************/
var Schema = {
    photo: {
        photo_id: {type: 'increments', nullable: false, primary: true},
        photo_url: {type: 'string', maxlength: 254, nullable: false}
    },
    user: {
        user_id: {type: 'increments', nullable: false, primary: true},
        user_name: {type: 'string', maxlength: 254, nullable: false},
        password: {type: 'string', maxlength: 150, nullable: false},
        email_id: {type: 'string', maxlength: 254, nullable: false, unique: true, validations: {isEmail: true}},
        photo_id: {type: 'integer', nullable: true, unsigned: true, references: 'photo.photo_id'},
        company: {type: 'string', maxlength: 254, nullable: false},
        introduction: {type: 'string', maxlength: 510, nullable: false},
        last_login: {type: 'dateTime', nullable: true},
        created_at: {type: 'dateTime', nullable: false},
    },
    vnf: {
        vnf_id: {type: 'increments', nullable: false, primary: true},
        vnf_name: {type: 'string', maxlength: 254, nullable: false},
        repo_url: {type: 'string', maxlength: 254, nullable: false},
        photo_id: {type: 'integer', nullable: true, unsigned: true, references: 'photo.photo_id'},
        submitter_id: {type: 'integer', nullable: false, unsigned: true, references: 'user.user_id'},
        lines_of_code: {type: 'integer', nullable: true, unsigned: true},
        versions: {type: 'integer', nullable: true, unsigned: true},
        no_of_developers: {type: 'integer', nullable: true, unsigned: true},
        no_of_stars: {type: 'integer', nullable: true, unsigned: true},
        license: {type: 'enum', nullable: false, values: ['MIT', 'GPL', 'GPL_V2', 'BSD', 'APACHE']},
        opnfv_indicator: {type: 'enum', nullable: false, values: ['gold', 'silver', 'platinum']},
        complexity: {type: 'enum', nullable: true, values: ['low', 'medium', 'high']},
        activity: {type: 'enum', nullable: true, values: ['low', 'medium', 'high']},
        last_updated: {type: 'dateTime', nullable: true},
    },
    tag: {
        tag_id: {type: 'increments', nullable: false, primary: true},
        tag_name: {type: 'string', maxlength: 150, nullable: false},
        is_vnf_name: {type: 'boolean', defaultTo: 'false'} 
    },
    vnf_tags: {
        vnf_tag_id: {type: 'increments', nullable: false, primary: true},
        tag_id: {type: 'integer', nullable: false, unsigned: true, references: 'tag.tag_id'},
        vnf_id: {type: 'integer', nullable: false, unsigned: true, references: 'vnf.vnf_id'},
    },
    vnf_contributors: {
        vnf_contributors_id: {type: 'increments', nullable: false, primary: true},
        user_id: {type: 'integer', nullable: false, unsigned: true, references: 'user.user_id'},
        vnf_id: {type: 'integer', nullable: false, unsigned: true, references: 'vnf.vnf_id'},
        created_at: {type: 'dateTime', nullable: false},
    }
};
module.exports = Schema;
