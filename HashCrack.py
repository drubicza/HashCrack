import marshal,zlib,base64
exec(marshal.loads(zlib.decompress(base64.b64decode("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"))))