﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Owin.Client.Http;
using Owin.Types;

namespace Owin.Client
{
    public static class RequestBuilder
    {
        public static IDictionary<string, object> FromRaw(string raw)
        {
            var stream = new MemoryStream(Encoding.UTF8.GetBytes(raw));

            var request = OwinRequest.Create();

            HttpParser.ParseRequest(stream, (method, path, protocol) =>
            {
                request.Method = method;
                var uri = new Uri(path);
                request.Protocol = protocol;
                BuildRequestFromUri(request, uri);
            },
            (key, value) => request.SetHeader(key, value));

            request.Body = stream;

            return request.Dictionary;
        }

        public static void BuildGet(IDictionary<string, object> environment, string url)
        {
            var uri = new Uri(url);
            var request = OwinRequest.Create(environment);
            request.Protocol = "HTTP/1.1";
            request.Method = "GET";

            BuildRequestFromUri(request, uri);
        }

        public static IDictionary<string, object> Get(string url)
        {
            if (url == null)
            {
                throw new ArgumentNullException("url");
            }

            OwinRequest request = CreateRequest(url, "GET");
            return request.Dictionary;
        }

        public static IDictionary<string, object> Post(string url)
        {
            OwinRequest request = CreateRequest(url, "POST");
            return request.Dictionary;
        }

        private static OwinRequest CreateRequest(string url, string method)
        {
            var uri = new Uri(url);
            var request = OwinRequest.Create();
            request.Protocol = "HTTP/1.1";
            request.Method = method;

            // Setup a empty stream by default
            var response = new OwinResponse(request);
            response.Body = new MemoryStream();

            BuildRequestFromUri(request, uri);
            return request;
        }

        private static void BuildRequestFromUri(OwinRequest request, Uri uri)
        {
            request.Host = uri.GetComponents(UriComponents.HostAndPort, UriFormat.Unescaped);
            request.PathBase = String.Empty;
            request.Path = uri.LocalPath;
            request.Scheme = uri.Scheme;
            request.QueryString = uri.Query.Length > 0 ? uri.Query.Substring(1) : String.Empty;
        }
    }
}
