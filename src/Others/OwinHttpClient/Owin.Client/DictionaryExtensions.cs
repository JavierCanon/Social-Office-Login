﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Owin.Types;

namespace Owin.Client
{
    public static class DictionaryExtensions
    {
        public static IDictionary<string, object> WithCredentials(this IDictionary<string, object> env, string user, string password)
        {
            string value = Convert.ToBase64String(Encoding.ASCII.GetBytes(user + ":" + password));
            return env.WithHeader("Authorization", "Basic " + value);
        }

        public static IDictionary<string, object> WithContentType(this IDictionary<string, object> env, string value)
        {
            return env.WithHeader("Content-Type", value);
        }

        public static IDictionary<string, object> WithHeader(this IDictionary<string, object> env, string key, string value)
        {
            var request = new OwinRequest(env);
            request.SetHeader(key, value);

            return request.Dictionary;
        }

        public static IDictionary<string, object> WithBody(this IDictionary<string, object> env, Stream stream)
        {
            var request = new OwinRequest(env);
            request.Body = stream;
            request.SetHeader("Content-Length", stream.Length.ToString());

            return request.Dictionary;
        }

        public static IDictionary<string, object> WithForm(this IDictionary<string, object> env, object postData)
        {
            return env.WithForm(GetDictionary(postData));
        }

        public static IDictionary<string, object> WithForm(this IDictionary<string, object> env, IDictionary<string, string> postData)
        {
            return env.WithContentType("application/x-www-form-urlencoded; charset=UTF-8")
                      .WithBody(GetRequestBody(postData));
        }

        private static IDictionary<string, string> GetDictionary(object postData)
        {
            var properties = new Dictionary<string, string>();
            foreach (var property in postData.GetType().GetProperties())
            {
                object value = property.GetValue(postData);
                properties[property.Name] = value == null ? value.ToString() : null;
            }

            return properties;
        }

        private static Stream GetRequestBody(IDictionary<string, string> postData)
        {
            if (postData != null)
            {
                var ms = new MemoryStream();
                bool first = true;
                var writer = new StreamWriter(ms);
                writer.AutoFlush = true;
                foreach (var item in postData)
                {
                    if (!first)
                    {
                        writer.Write("&");
                    }
                    writer.Write(item.Key);
                    writer.Write("=");
                    writer.Write(Uri.EscapeDataString(item.Value));
                    writer.WriteLine();
                    first = false;
                }

                ms.Seek(0, SeekOrigin.Begin);
                return ms;
            }

            return Stream.Null;
        }
    }
}
