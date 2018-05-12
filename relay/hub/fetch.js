// vim: ts=4:sw=4:expandtab

'use strict';

const nodeFetch = require('node-fetch');
const http = require('http');
const https = require('https');


const agents = {
    https: new https.Agent({keepAlive: true}),
    http: new http.Agent({keepAlive: true})
};

async function fetch(url_or_request, options) {
    /* Add keepalive support */
    let url;
    if (url_or_request instanceof nodeFetch.Request) {
        url = url_or_request.url;
        options = url_or_request;
    } else {
        url = url_or_request;
    }
    options = options || {};
    if (!options.agent) {
        const scheme = url.split('://')[0];
        options.agent = agents[scheme];
    }
    options.headers = options.headers || new nodeFetch.Headers();
    options.headers.set('Connection', 'keep-alive');
    const body = options.json && JSON.stringify(options.json);
    if (body) {
        options.headers.set('Content-Type', 'application/json; charset=utf-8');
        options.body = body;
    }
    return await nodeFetch(url_or_request, options);
}

fetch.Headers = nodeFetch.Headers;
fetch.Request = nodeFetch.Request;
fetch.Response = nodeFetch.Response;
fetch.Body = nodeFetch.Body;

module.exports = fetch;
