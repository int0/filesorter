/*
Copyright 2017 Volodymyr Pikhur

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF
OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/
#include <windows.h>
#include <tchar.h>
#include <strsafe.h>

#include "md5.h"
#include "sha1.h"
#include "sha2.h"

VOID GetBufferMD5( __in PUCHAR Buffer, __in ULONG BufferSize, __out PUCHAR Md5 )
{
    MD5_CTX ctx;
    MD5Init( &ctx );
    MD5Update( &ctx, Buffer, BufferSize );
    MD5Final( &ctx );

    memcpy( Md5, ctx.digest, 16 );
}

VOID GetBufferSHA1( __in PUCHAR Buffer, __in ULONG BufferSize, __out PUCHAR Sha1 )
{
    sha1_ctx ctx;
    sha1_begin( &ctx );
    sha1_hash( &Buffer[0], BufferSize, &ctx );
    sha1_end( Sha1, &ctx );
}

VOID GetBufferSHA256( __in PUCHAR Buffer, __in ULONG BufferSize, __out PUCHAR Sha256 )
{
    sha256_ctx ctx;
    sha256_begin( &ctx );
    sha256_hash( &Buffer[0], BufferSize, &ctx );
    sha256_end( Sha256, &ctx );
}

VOID GetHexString( __in PUCHAR Buffer, __in ULONG Size, __out TCHAR *OutString, SIZE_T OutStrSize )
{
    ULONG nPos = 0;
    ULONG nRounds = Size / 8;

    for( ULONG i = 0; i < nRounds; i++ )
    {
        ULONG64 b64 = _byteswap_uint64(*(PULONG64)&Buffer[i*8]);
        StringCchPrintf( &OutString[i*16], OutStrSize - i * 16, _T("%016I64x"), b64 );
        nPos += 16;
    }

    for ( ULONG i = 0; i < Size - nRounds * 8; i++ )
    {
        StringCchPrintf( &OutString[nPos], OutStrSize - nPos, _T("%02x"), Buffer[nPos/2] );
    }    
}