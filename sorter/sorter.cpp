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
#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <strsafe.h>
#include <Msi.h>

#include "../shared/hash/hash_helpers.h"

#pragma comment( lib, "msi.lib" )

TCHAR *OutFile;
TCHAR OutPath[MAX_PATH*4];
size_t OutDirLen, OutFileLen;

struct
{
    BOOL CopyFiles;
    BOOL SkipUnknown;
} g_Flags;

TCHAR *FILETYPE_NAME[] =
{
    _T("!unk"),
    
    _T("os2"),
    _T("pe"),
    _T("elf"),
    _T("macho"),
    _T("dex"),                      /// Dalvik executable for Android
    
    _T("msi"),
    _T("rar"),
    _T("zip"),
    _T("7z"),
    _T("cab"),
    _T("tar"),
    _T("ace"),
    _T("gzip"),
    _T("jar"),
    _T("bz2"),
    _T("apk"),


    _T("pdf"),
    _T("xls"),
    _T("doc"),
    _T("chm"),
    _T("mht"),
    _T("hlp"),
    _T("ms-cfb"),
    
    _T("bmp"),
    _T("jpg"),
    _T("tiff"),
    _T("png"),
    _T("gif"),
    _T("tga"),
    _T("ogg"),
    _T("p3ml"),
    _T("swf"),
    _T("flv"),

    _T("reg"),
    _T("vbs"),
    _T("py"),
    _T("ini"),
    _T("html"),
    _T("php"),
    _T("txt"),
    _T("lua"),
    _T("perl"),
    _T("bat"),
    _T("rtf"),

    _T("luac"),
    _T("class"),
    _T("pyc"),
    _T("pcap"),

    _T("dmp"),
    _T("lnk"),
    _T("pif"),
    _T("regf"),
    _T("xml"),
    _T("wav"),
    _T("wmv"),
};

typedef enum _FILETYPE
{
    FT_UNKNOWN,
    ///< EXECUTABLE FILES
    FT_NE,
    FT_PE,
    FT_ELF,
    FT_MACHO,
    FT_DEX,
    ///< ARCHIVE FILES
    FT_MSI,
    FT_RAR,
    FT_ZIP,
    FT_7Z,
    FT_CAB,
    FT_TAR,
    FT_ACE,
    FT_GZIP,
    FT_JAR,                              ///< Java archive
    FT_BZ2,
    FT_APK,
    ///< DOCUMENT FILES
    FT_PDF,                             ///< Adobe PDF document
    FT_XLS,                             ///< MS Excel document
    FT_DOC,                             ///< MS Word document
    FT_CHM,
    FT_MHT,
    FT_HLP,
    FT_MS_CFB,                          ///< MS Compound File Binary File Format (XLS, DOC,DB,MSI, etc)
    ///< IMAGE FILE TYPES
    FT_BMP,
    FT_JPG,
    FT_TIFF,
    FT_PNG,
    FT_GIF,
    FT_TGA,
    FT_OGG,
    FT_P3ML,
    ///< FLASH FILE TYPES
    FT_SWF,
    FT_FLV,
    ///< TEXT FILE TYPES
    FT_REG,
    FT_VBS,
    FT_PY,
    FT_INI,
    FT_HTML,
    FT_PHP,
    FT_TXT,
    FT_LUA,
    FT_PERL,
    FT_BAT,                             ///< Windows batch script
    FT_RTF,                             ///< Rich text format word processing file
    ///< BINARY COMPILED FILES
    FT_LUAC,                            ///< Lua compiled file
    FT_CLASS,                           ///< Java compiled class file
    FT_PYC,                             ///< Python compiled file
    FT_PCAP,
    ///< MISC
    FT_DMP,                             ///< Windows dump file
    FT_LNK,                             ///< Windows shortcut
    FT_PIF,
    FT_REGF,                            ///< Windows registry hive
    FT_XML,
    FT_WAV,
    FT_WMV,
} FILETYPE, *PFILETYPE;



//
// MACH-O types
// 
//////////////////////////////////////////////////////////////////////////

#define 	MH_MAGIC32   0xfeedface
#define 	MH_MAGIC64   0xfeedfacf

typedef int	CPU_TYPE_T;
typedef int	CPU_SUBTYPE_T;

typedef struct _MACH_HEADER
{
    ULONG magic;
    CPU_TYPE_T cputype;
    CPU_SUBTYPE_T cpusubtype;
    ULONG filetype;
    ULONG ncmds;
    ULONG sizeofcmds;
    ULONG flags;
} MACH_HEADER, *PMACH_HEADER;

//////////////////////////////////////////////////////////////////////////


BOOL FORCEINLINE IsPeFile( PUCHAR Buffer, ULONG Size )
{
    PIMAGE_DOS_HEADER mz = (PIMAGE_DOS_HEADER)Buffer;
    PIMAGE_NT_HEADERS pe;

    if( Size < sizeof(*mz) + sizeof(*pe) )
        return FALSE;

    pe = (PIMAGE_NT_HEADERS)( Buffer + mz->e_lfanew );

    __try
    {
        if( IMAGE_DOS_SIGNATURE != mz->e_magic || 
            IMAGE_NT_SIGNATURE != pe->Signature )
            return FALSE;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }

    return TRUE;
}

BOOL FORCEINLINE IsNE( PUCHAR Buffer, ULONG Size )
{
    PIMAGE_DOS_HEADER mz = (PIMAGE_DOS_HEADER)Buffer;
    PIMAGE_OS2_HEADER ne;

    if( Size < sizeof(*mz) + sizeof(*ne) )
        return FALSE;

    ne = (PIMAGE_OS2_HEADER)( Buffer + mz->e_lfanew );

    if( IMAGE_DOS_SIGNATURE != mz->e_magic || 
        IMAGE_OS2_SIGNATURE != ne->ne_magic )
            return FALSE;

    return TRUE;
}

BOOL FORCEINLINE IsMacho( PUCHAR Buffer, ULONG Size )
{
    PMACH_HEADER mh = (PMACH_HEADER)Buffer;

    if( Size < sizeof(*mh) )
        return FALSE;

    if( MH_MAGIC32 == mh->magic ||
        MH_MAGIC64 == mh->magic)
        return TRUE;

    return FALSE;
}

BOOL FORCEINLINE IsPDF( PUCHAR Buffer, ULONG Size )
{
    return ( *(PULONG)&Buffer[0] == _byteswap_ulong( '%PDF' ) );
}

// 52 61 72 21 1A 07 00
BOOL FORCEINLINE IsRAR( PUCHAR Buffer, ULONG Size )
{
    return ( *(PULONG)&Buffer[0] == _byteswap_ulong( 'Rar!' ) && 
        0x1A == Buffer[4] &&
        0x07 == Buffer[5] &&
        0x00 == Buffer[6] );
}

//4D 44 4D 50 93 A7   MDMP
BOOL FORCEINLINE IsDMP( PUCHAR Buffer, ULONG Size )
{
    return ( ( *(PULONG)&Buffer[0] == _byteswap_ulong( 'PAGE' ) && *(PULONG)&Buffer[4] == _byteswap_ulong( 'DU64' ) ) ||
        ( *(PULONG)&Buffer[0] == _byteswap_ulong( 'PAGE' ) && *(PULONG)&Buffer[4] == _byteswap_ulong( 'DUMP' ) ) ||
        ( *(PULONG)&Buffer[0] == _byteswap_ulong( 'MDMP' ) && *(PUSHORT)&Buffer[4] == 0xA793 ) );
}

//89  50  4e  47  0d  0a  1a  0a
BOOL FORCEINLINE IsPNG( PUCHAR Buffer, ULONG Size )
{
    return ( *(PULONG)&Buffer[0] == _byteswap_ulong( '\x89PNG' ) && *(PULONG)&Buffer[4] == 0x0a1a0a0d );
}

BOOL FORCEINLINE IsJPG( PUCHAR Buffer, ULONG Size )
{
    return ( *(PULONG)&Buffer[0] == 0xE1FFD8FF ||
        *(PULONG)&Buffer[0] == 0xE0FFD8FF );
}

BOOL FORCEINLINE IsWAV( PUCHAR Buffer, ULONG Size )
{
    return ( *(PULONG)&Buffer[0] == _byteswap_ulong('RIFF') );
}

BOOL FORCEINLINE IsOGG( PUCHAR Buffer, ULONG Size )
{
    return ( *(PULONG)&Buffer[0] == _byteswap_ulong('OggS') );
}

BOOL FORCEINLINE IsP3ML( PUCHAR Buffer, ULONG Size )
{
    return ( *(PULONG)&Buffer[0] == _byteswap_ulong('P3ML') );
}

//
// Almost all MS formats DOC, XLS, MSI, DB (Thumbs)
//D0 CF 11 E0 A1 B1 1A E1
BOOL FORCEINLINE IsMSContainer( PUCHAR Buffer, ULONG Size )
{
    return ( *(PULONG)&Buffer[0] == 0xE011CFD0 && *(PULONG)&Buffer[4] == 0xE11AB1A1 );
}

//
// CA FE BA BE
BOOL FORCEINLINE IsCLASS( PUCHAR Buffer, ULONG Size )
{
    return ( *(PULONG)&Buffer[0] == 0xBEBAFECA );
}

//50 4B 03 04
BOOL FORCEINLINE IsZIP( PUCHAR Buffer, ULONG Size )
{
    return ( *(PULONG)&Buffer[0] == 0x04034B50 );
}

//
// 37 7A BC AF 27 1C
BOOL FORCEINLINE Is7Z( PUCHAR Buffer, ULONG Size )
{
    return ( *(PULONG)&Buffer[0] == 0xAFBC7A37 && *(PUSHORT)&Buffer[4] == 0x1C27 );
}
//
//4D 53 43 46	 	MSCF
BOOL FORCEINLINE IsCAB( PUCHAR Buffer, ULONG Size )
{
    return ( *(PULONG)&Buffer[0] == 0x4643534D );
}

//
//1F 8B 08
BOOL FORCEINLINE IsGZIP( PUCHAR Buffer, ULONG Size )
{
    return ( 0x1F == Buffer[0] &&
             0x8B == Buffer[1] &&
             0x08 == Buffer[2] );
}

//
// 7F 45 4C 46
BOOL FORCEINLINE IsELF( PUCHAR Buffer, ULONG Size )
{
    return ( *(PULONG)&Buffer[0] == 0x464C457F );
}

//4C 00 00 00 01 14 02 00
BOOL FORCEINLINE IsLNK( PUCHAR Buffer, ULONG Size )
{
    return ( *(PULONG)&Buffer[0] == 0x0000004C && *(PULONG)&Buffer[4] == 0x00021401 );
}

//
//4C 4E 02 00
BOOL FORCEINLINE IsHLP( PUCHAR Buffer, ULONG Size )
{
    return ( *(PULONG)&Buffer[0] == 0x00024E4C );
}

//47 49 46 38 37 61  	GIF87a
//47 49 46 38 39 61	 	GIF89a
BOOL FORCEINLINE IsGIF( PUCHAR Buffer, ULONG Size )
{
    return ( *(PULONG)&Buffer[0] == 0x38464947 && 
        ( *(PUSHORT)&Buffer[4] == 0x6137 || *(PUSHORT)&Buffer[4] == 0x6139 ) );
}

//7B 5C 72 74 66 31	 	{\rtf1
BOOL FORCEINLINE IsRTF( PUCHAR Buffer, ULONG Size )
{
    return ( 0 == memcmp( Buffer, "{\\rtf", 5 ) );
}

//FE FF         - unicode marker
//EF BB BF      - unicode marker
BOOL FORCEINLINE IsTXT( PUCHAR Buffer, ULONG Size )
{
    return FALSE;
}

//
//FF FE unicode reg file
BOOL FORCEINLINE IsREG( PUCHAR Buffer, ULONG Size )
{
    return ( 0 == memcmp( Buffer, "REGEDIT", 7 ) ||
        ( *(PUSHORT)&Buffer[0] == 0xFEFF && 0 == memcmp( &Buffer[2], L"Windows Registry Editor Version", 31 * 2 ) ) );
}

//49 54 53 46	 	ITSF
BOOL FORCEINLINE IsCHM( PUCHAR Buffer, ULONG Size )
{
    return ( *(PULONG)&Buffer[0] == _byteswap_ulong('ITSF') );
}

//72 65 67 66	 	regf
BOOL FORCEINLINE IsREGF( PUCHAR Buffer, ULONG Size )
{
    return ( *(PULONG)&Buffer[0] == _byteswap_ulong('regf') );
}

//46 57 53	 	FWS
//43 57 53	 	CWS
BOOL FORCEINLINE IsSWF( PUCHAR Buffer, ULONG Size )
{
    if( 'W' ==  Buffer[1] && 'S' ==  Buffer[2] )
    {
        return ( 'F' ==  Buffer[0] || 
                 'C' ==  Buffer[0] );
    }
    return FALSE;
}

//46 4C 56 01	 	FLV
BOOL FORCEINLINE IsFLV( PUCHAR Buffer, ULONG Size )
{
    return ( *(PULONG)&Buffer[0] == _byteswap_ulong('FLV\x01') );
}

BOOL FORCEINLINE IsJAR( PUCHAR Buffer, ULONG Size )
{
    for ( ULONG i = 4; i < 0x80; i++ )
    {
        if( 0 == memcmp( &Buffer[i], "META-INF", 8 ) ||
            0 == memcmp( &Buffer[i], ".class", 6 ) )
            return TRUE;
    }

    return FALSE;
}

BOOL FORCEINLINE IsXML( PUCHAR Buffer, ULONG Size )
{
    return ( *(PULONG)&Buffer[0] == _byteswap_ulong('<?xm') );
}

BOOL FORCEINLINE IsPHP( PUCHAR Buffer, ULONG Size )
{
    return ( *(PULONG)&Buffer[0] == _byteswap_ulong('<?ph') );
}

BOOL FORCEINLINE IsHTML( PUCHAR Buffer, ULONG Size )
{
    if( *(PULONG)&Buffer[0] == _byteswap_ulong('<!DO') )
        return TRUE;
    else if ( *(PULONG)&Buffer[0] == _byteswap_ulong('<htm') )
        return TRUE;

    return FALSE;
}

BOOL FORCEINLINE IsTAR( PUCHAR Buffer, ULONG Size )
{
    if( Size < 0x200 )
        return FALSE;

    if( 0 == memcmp( &Buffer[0x101], "ustar  ", 8 ) ||
        0 == memcmp( &Buffer[0x101], "GNUtar ", 8 ) )
        return TRUE;

    return FALSE;
}



BOOL FORCEINLINE IsINI( PUCHAR Buffer, ULONG Size )
{
    ULONG BytesToScan = ( 128 < Size ) ? 128 : Size;

    if( Buffer[0] == '[' )
    {
        for ( ULONG i = 1; i < BytesToScan; i++ )
        {
            if( Buffer[i+0] == ']' &&
                Buffer[i+1] == '\r' &&
                Buffer[i+2] == '\n' )
                return TRUE;
            else if( Buffer[i] == '\r' || Buffer[i] == '\n' )
                break;
        }
    }
    else
    {
        for ( ULONG i = 0; i < BytesToScan; i++ )
        {
            if( Buffer[i+0] == ']' &&
                Buffer[i+1] == '\r' &&
                Buffer[i+2] == '\n' )
                return TRUE;
            else if( Buffer[i] == '\r' || Buffer[i] == '\n' )
                break;
        }
    }

    return FALSE;
}

BOOL FORCEINLINE IsBMP( PUCHAR Buffer, ULONG Size )
{
    return ( *(PUSHORT)&Buffer[0] == _byteswap_ushort('BM') );
}

BOOL FORCEINLINE IsBZ2( PUCHAR Buffer, ULONG Size )
{
    return ( 0 == memcmp( &Buffer[0], "BZh91AY&SY", 10 ) );
}

BOOL FORCEINLINE IsWMV( PUCHAR Buffer, ULONG Size )
{
    return ( *(PULONG64)&Buffer[0] == 0x11CF668E75B22630 );
}

BOOL FORCEINLINE IsDEX( PUCHAR Buffer, ULONG Size )
{
    return ( *(PULONG)&Buffer[0] == 0x0A786564 );
}

BOOL FORCEINLINE IsAPK( PUCHAR Buffer, ULONG Size )
{
    for ( ULONG i = 4; i < 0x80; i++ )
    {
        if( 0 == memcmp( &Buffer[i], "Android", 7 ) )
            return TRUE;
    }

    if( Size > 0x200 )
    {
        for ( ULONG i = Size - 0x200; i < Size - 8; i++ )
        {
            if( 0 == memcmp( &Buffer[i], "classes.dex", 11 ) ||
                0 == memcmp( &Buffer[i], "resources.arsc", 14 ) ||
                0 == memcmp( &Buffer[i], "Android", 7 ) )
                return TRUE;
        }
    }
    return FALSE;
}


BOOL FORCEINLINE IsPCAP( PUCHAR Buffer, ULONG Size )
{
    return ( *(PULONG)&Buffer[0] == 0xA1B2C3D4 );
}


FILETYPE IdentifyFile( TCHAR *FilePath, PUCHAR Buffer, ULONG Size )
{
    if( IsPeFile( Buffer, Size ) )
        return FT_PE;

    if( IsMacho( Buffer, Size ) )
        return FT_MACHO;

    if( IsPDF( Buffer,Size ) )
        return FT_PDF;

    if( IsRAR( Buffer, Size ) )
        return FT_RAR;

    if( IsWMV( Buffer, Size ) )
        return FT_WMV;

    if( IsDMP( Buffer, Size ) )
        return FT_DMP;

    if( IsDEX( Buffer, Size ) )
        return FT_DEX;

    if( IsZIP( Buffer, Size ) )
    {
        if( IsJAR( Buffer, Size ) )
        {
            return FT_JAR;
        }

        if( IsAPK( Buffer, Size ) )
        {
            return FT_APK;
        }

        return FT_ZIP;
    }

    if( IsBZ2( Buffer, Size ) )
        return FT_BZ2;

    if( Buffer[0] == 0xEF && 
        Buffer[1] == 0xBB &&
        Buffer[2] == 0xBF )
    {
        if( IsZIP( &Buffer[3], Size-3 ) )
        {
            if( IsJAR( &Buffer[3], Size-3 ) )
            {
                return FT_JAR;
            }

            if( IsAPK( Buffer, Size ) )
            {
                return FT_APK;
            }

            return FT_ZIP;
        }
    }

    if( IsPCAP( Buffer, Size ) )
        return FT_PCAP;

    if( IsTAR( Buffer, Size ) )
        return FT_TAR;

    if( IsXML( Buffer, Size ) )
        return FT_XML;

    if( IsPHP( Buffer, Size ) )
        return FT_PHP;

    if( IsHTML( Buffer, Size ) )
        return FT_HTML;
    
    if( IsBMP( Buffer, Size ) )
        return FT_BMP;
    
    if( IsGZIP( Buffer, Size ) )
        return FT_GZIP;

    if( IsJPG( Buffer, Size ) )
        return FT_JPG;

    if( IsPNG( Buffer, Size ) )
        return FT_PNG;

    if( IsCLASS( Buffer, Size ) )
        return FT_CLASS;

    if( Is7Z( Buffer, Size ) )
        return FT_7Z;

    if( IsCAB( Buffer, Size ) )
        return FT_CAB;

    if( IsWAV( Buffer, Size ) )
        return FT_WAV;

    if( Size > 0x204 && IsMSContainer( Buffer, Size ) )
    {
        if( ERROR_SUCCESS == MsiVerifyPackage( FilePath ) )
            return FT_MSI;

        if( 0x00C1A5EC == *(PULONG)&Buffer[0x200] )
            return FT_DOC;

        return FT_MS_CFB;
    }

    if( IsELF( Buffer, Size ) )
        return FT_ELF;

    if( IsLNK( Buffer, Size ) )
        return FT_LNK;

    if( IsNE( Buffer, Size ) )
        return FT_NE;

    if( IsGIF( Buffer, Size ) )
        return FT_GIF;

    if( IsRTF(Buffer, Size ) )
        return FT_RTF;

    if( IsCHM( Buffer, Size ) )
        return FT_CHM;

    if( IsFLV( Buffer, Size ) )
        return FT_FLV;

    if( IsSWF( Buffer, Size ) )
        return FT_SWF;

    if( IsREG( Buffer, Size ) )
        return FT_REG;

    if( IsREGF( Buffer, Size ) )
        return FT_REGF;

    if( IsOGG( Buffer, Size ) )
        return FT_OGG;

    if( IsP3ML( Buffer, Size ) )
        return FT_P3ML;

    if( IsINI( Buffer, Size ) )
        return FT_INI;

    return FT_UNKNOWN;
}

BOOL ReadFileHeader( TCHAR *FilePath, ULONG FileSize, PUCHAR *Header )
{
    BOOL Res = FALSE;
    HANDLE FileHandle;
    ULONG BytesRead;


    if( INVALID_HANDLE_VALUE == 
        ( FileHandle = CreateFile( FilePath, FILE_GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL ) ) )
    {
        return FALSE;
    }    

    *Header = (PUCHAR)malloc( FileSize );

    if( NULL != *Header )
    {
        if( ReadFile( FileHandle, *Header, FileSize, &BytesRead, NULL ) &&
            FileSize == BytesRead )
        {
            Res = TRUE;
        }
    }

    CloseHandle( FileHandle );

    if( !Res && *Header )
        free( Header );
    
    return Res;
}

VOID ScanFile( TCHAR *FilePath, ULONG FileSize )
{
    TCHAR *FileName, *TypeName;
    FILETYPE ft;
    PUCHAR Buffer;
    UCHAR FileMd5[16];
    UCHAR FileSHA256[32];
    TCHAR FileMd5Text[33];
    TCHAR FileSHA256Text[65];

    __try
    {
        if( NULL != ( FileName = _tcsrchr( FilePath, _T('\\') ) ) || 
            NULL != ( FileName = _tcsrchr( FilePath, _T('/') ) ) )
        {
            FileName++;
        }
        else
        {
            FileName = FilePath;
        }

        if( ReadFileHeader( FilePath, FileSize, &Buffer ) )
        {
            GetBufferMD5( Buffer, FileSize, FileMd5 );
            GetBufferSHA256( Buffer, FileSize, FileSHA256 );
            ft = IdentifyFile( FilePath, Buffer, FileSize );
            free( Buffer );
        }
        else
        {
            ft = FT_UNKNOWN;
        }

        if( ft == FT_UNKNOWN && g_Flags.SkipUnknown )
            return;
        
        TypeName = FILETYPE_NAME[ft];

        GetHexString( FileMd5, sizeof(FileMd5), FileMd5Text, _countof(FileMd5Text) );
        GetHexString( FileSHA256, sizeof(FileSHA256), FileSHA256Text, _countof(FileSHA256Text) );

        StringCchPrintf( OutFile, OutFileLen / sizeof(TCHAR), _T("%s%s\\"), OutPath, FILETYPE_NAME[ft] );

        if( INVALID_FILE_ATTRIBUTES == GetFileAttributes( OutFile ) )
        {
            CreateDirectory( OutFile, NULL );
        }

        StringCchPrintf( OutFile, OutFileLen / sizeof(TCHAR), _T("%s%s\\%c"), OutPath, FILETYPE_NAME[ft], FileMd5Text[0] );
        CreateDirectory( OutFile, NULL );
        
        StringCchPrintf( OutFile, OutFileLen / sizeof(TCHAR), _T("%s%s\\%c\\%c%c"), OutPath, FILETYPE_NAME[ft], 
            FileMd5Text[0], FileMd5Text[1], FileMd5Text[2] );
        CreateDirectory( OutFile, NULL );
        
        StringCchPrintf( OutFile, OutFileLen / sizeof(TCHAR), _T("%s%s\\%c\\%c%c\\%c%c"), OutPath, FILETYPE_NAME[ft], 
            FileMd5Text[0], FileMd5Text[1], FileMd5Text[2], FileMd5Text[3], FileMd5Text[4] );
        CreateDirectory( OutFile, NULL );

        StringCchPrintf( OutFile, OutFileLen / sizeof(TCHAR), _T("%s%s\\%c\\%c%c\\%c%c\\%s_%s.vir"), OutPath, FILETYPE_NAME[ft], 
            FileMd5Text[0], FileMd5Text[1], FileMd5Text[2], FileMd5Text[3], FileMd5Text[4], FileMd5Text, FileSHA256Text );

        if( INVALID_FILE_ATTRIBUTES == GetFileAttributes( OutFile ) )
        {
            BOOL Move = TRUE;
            
            if( ft == FT_UNKNOWN && g_Flags.SkipUnknown )
            {
                Move = FALSE;
                TypeName = _T("SKIPPED");
            }

            if( Move )
            {
                if( !MoveFile( FilePath, OutFile ) )
                {
                    TypeName = _T("ERROR M");
                }
            }
        }
        else
        {
            TypeName = _T("SKIPPED");
        }
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        TypeName = _T("ERROR E");
    }

    _tprintf( _T( "%-8s - %s\n" ), TypeName, FilePath );
}

void ScanDirectory( TCHAR *path )
{
    int res = 0;
    int MaxDirSizeInBytes = 0x1000 * sizeof(TCHAR);
    int MaxDirSizeInTChars =  MaxDirSizeInBytes / sizeof(TCHAR);

    TCHAR *dir = (TCHAR *)LocalAlloc( LMEM_ZEROINIT, MaxDirSizeInBytes );

    if( dir )
    {
        _tcscpy_s( dir, MaxDirSizeInTChars, path );

        size_t pos = _tcslen(dir) - 1;

        if( dir[ pos ] == _T('\\') )
            _tcscat_s( dir, MaxDirSizeInTChars - _tcslen(dir), _T("*") );
        else
            _tcscat_s( dir, MaxDirSizeInTChars - _tcslen(dir), _T("\\*") );

        WIN32_FIND_DATA fdata = {0};
        HANDLE hFind = FindFirstFile( dir, &fdata );
        dir[ _tcslen(dir) - 1 ] = 0;

        if( hFind != INVALID_HANDLE_VALUE )
        {
            do
            {
                if( _tcscmp( fdata.cFileName, _T(".") ) == 0 ||
                    _tcscmp( fdata.cFileName, _T("..") ) == 0 ) 
                    continue;

                if( (fdata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) 
                    == FILE_ATTRIBUTE_DIRECTORY )
                {
                    TCHAR *fullpath = (TCHAR *)LocalAlloc( LMEM_ZEROINIT, MaxDirSizeInBytes );
                    _tcscpy_s( fullpath, MaxDirSizeInTChars, dir );
                    _tcscat_s( fullpath, MaxDirSizeInTChars - _tcslen(fullpath), fdata.cFileName );
                    ScanDirectory( fullpath );
                    LocalFree( fullpath );
                }
                else
                {
                    TCHAR *fullpath = (TCHAR *)LocalAlloc( LMEM_ZEROINIT, MaxDirSizeInBytes );
                    _tcscpy_s( fullpath, MaxDirSizeInTChars, dir );
                    _tcscat_s( fullpath, MaxDirSizeInTChars - _tcslen(fullpath), fdata.cFileName );

                    // do stuff here

                    if( fdata.nFileSizeLow < 64 * 1024 * 1024 )
                    {
                        ScanFile( fullpath, fdata.nFileSizeLow );
                    }                    

                    LocalFree( fullpath );
                }
            } while ( FindNextFile( hFind, &fdata ) );

            FindClose(hFind);
        }
        LocalFree( dir );	
    }	
}


int _tmain(int argc, _TCHAR* argv[])
{    
    if( argc < 3 )
    {
        printf( "usage: tool.exe <params> <in dir> <out dir>\n" );
        return 0;
    }

    for( int i = 1; i < argc; i++ )
    {
        if( 0 == _tcsicmp( argv[i], _T("--copy") ) )
        {
            g_Flags.CopyFiles = TRUE;
        }
        else if ( 0 == _tcsicmp( argv[i], _T("--skip_unk") ) )
        {
            g_Flags.SkipUnknown = TRUE;
        }
    }

    PCHAR Msg;    

    StringCchCopy( OutPath, _countof(OutPath), argv[argc-1] );
    StringCchLength( OutPath, _countof(OutPath), &OutDirLen );

    if( OutPath[OutDirLen-1] != _T('\\') || 
        OutPath[OutDirLen-1] != _T('/') )
    {
        StringCchCat( OutPath, _countof(OutPath), _T("\\") );
        OutDirLen++;
    }

    OutFileLen = sizeof(OutPath) + MAX_PATH * sizeof(TCHAR);
    OutFile = (TCHAR *)malloc( OutFileLen );

    if( NULL == OutFile )
    {
        Msg = "Out of memory";
        goto _ReportError;
    }

    ScanDirectory( argv[argc-2] );

    Msg = "Done!";

_ReportError:

    printf( "%s\n", Msg );
    
    return 0;
}

