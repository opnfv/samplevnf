/*******************************************************************************
 * Copyright (c) 2017 Kumar Rishabh and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License, Version 2.0
 * which accompanies this distribution, and is available at
 * http://www.apache.org/licenses/LICENSE-2.0
 *******************************************************************************/

$(document).ready( function() {

    //getVnfs : get 5 main VNFs using typeahead
    var getVnfs = new Bloodhound({
        datumTokenizer: Bloodhound.tokenizers.obj.whitespace('vnf_name'),
        queryTokenizer: Bloodhound.tokenizers.obj.whitespace('vnf_name'),
        remote: {
            url: '/search_vnf?key=%QUERY',
            wildcard: '%QUERY'
        },
        limit: 5
    });

    getVnfs.initialize();
    $('#scrollable-dropdown-menu #vnf_name.typeahead').typeahead(
    {
        hint: true,
        highlight: true,
        minLength: 1
    },
    {
        name: 'vnf_name',
        display: 'vnf_name',
        limit: 5,
        source: getVnfs.ttAdapter()
    });

    //getTags : get 5 main tags using typeahead
    var getTags = new Bloodhound({
        datumTokenizer: Bloodhound.tokenizers.obj.whitespace('tag_name'),
        queryTokenizer: Bloodhound.tokenizers.obj.whitespace('tag_name'),
        remote: {
            url: '/search_tag?key=%QUERY',
            wildcard: '%QUERY'
        },
        limit: 5
    });

    getTags.initialize();
    $('#scrollable-dropdown-menu #tag_name.typeahead').typeahead(
    {
        hint: true,
        highlight: true,
        minLength: 1
    },
    {
        name: 'tag_name',
        display: 'tag_name',
        limit: 5,
        source: getTags.ttAdapter()
    });

    $("#add_vnf_tag_association_button").on('click',function(){
        event.preventDefault();
        var vnf_name = $("#vnf_name").val() ;

        $.ajax({
            url: '/vnf_tag_association',
            type: 'post',
            dataType: 'json',
            data: $('form#add_vnf_tag_association_form').serialize(),
            success: function(data) {
                    $('#modal3').modal('close');
                    $('form#add_vnf_tag_association_form').trigger('reset');
                    Materialize.toast('Successfully added the TAG to the VNF!', 3000, 'rounded');
            },
            error: function (error) {
                Materialize.toast(error['responseJSON']['error'], 3000, 'rounded');
            }
        });
    });

});
