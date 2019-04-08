<?php

/**
 * 
 * 字符串类
 *
 */
class UtilString
{
    /**
     * 分割字符串
     * @param string $sString 要分割的字符串
     * @param string $sDelimiter 分割符,默认/
     * @param int $iMax 最大分割层
     * @param int $iNum 每层字符数
     * @return string 分割后的字符串
     */
    public static function cutStr( string $sString, string $sDelimiter = '/', int $iMax = 4, int $iNum = 1 ): string
    {
        $l_strings = str_split( $sString, $iNum );
        $s_string = implode( $sDelimiter, array_splice( $l_strings, 0, $iMax ) );
        $s_string .= implode( '', $l_strings );
        return $s_string;
    }
    
    /**
     * 按微博规则获取内容长度
     * @param string $sString 内容
     * @return int
     */
    /*public static function weiboLen( string $sString ): int
    {
        $s_string = self::iconv( $sString, 'utf-8' );
        $i_bey_len = strlen( $s_string );//字符数
        $i_mb_len = mb_strlen( $s_string, 'utf-8' );//utf-8字符数
        $i_cb_len = ($i_bey_len - $i_mb_len) / 2;//中文字符数
        return ceil( ($i_mb_len - $i_cb_len)/2 ) + $i_cb_len;
    }*/
    
    /**
     * 获取字符串编码
     * @param string $sString 输入字符串
     * @return string 返回编码,失败返回空字符串
     */
    public static function getEncoding( string $sString ): string
    {
        $l_encoding_list = array( 'gb2312', 'gbk', 'utf-8' );
        $m_encoding = mb_detect_encoding( $sString, $l_encoding_list, true );
        if ( in_array( $m_encoding, $l_encoding_list, true ) )
        {
            return $m_encoding;
        } elseif ( $m_encoding )
        {
            return 'gbk';//一般情况下都是gbk
        } else 
        {
            return '';
        }
    }
    
    /**
     * 转换字符串编码
     * @param string $sString 输入字符串
     * @param string $sEncoding 要转换的编码
     * @param string $sFromEncoding 强制要转换的编码,默认自动检测
     * @return string 已转换编码的字符串
     */
    public static function iconv( string $sString, string $sEncoding, string $sFromEncoding = '' ): string
    {
        $s_encoding = $sFromEncoding ?: self::getEncoding( $sString );
        if( empty( $s_encoding ) || $s_encoding == $sEncoding )
        {
            return $sString;
        } else 
        {
            return mb_convert_encoding( $sString, $sEncoding, $s_encoding );
        }
    }
    
    /**
     * 转换字符串编码数组
     * @param array $aStringArr 输入字符串数组
     * @param string $sEncoding 要转换的编码
     * @param string $sFromEncoding 强制要转换的编码,默认自动检测
     * @return array 已转换的字符串数组
     */
    public static function iconvArray( array $aStringArr, string $sEncoding, string $sFromEncoding = '' ): array
    {
        foreach( $aStringArr as &$mStringArr_v )
        {
            if ( is_string( $mStringArr_v ) )
            {
                $s_encoding = $sFromEncoding ?: self::getEncoding( $mStringArr_v );
                if( $s_encoding && $s_encoding != $sEncoding )
                {
                    $mStringArr_v = mb_convert_encoding( $mStringArr_v, $sEncoding, $s_encoding );
                }
            } elseif ( is_array( $mStringArr_v ) )
            {
                $mStringArr_v = self::iconvArray( $mStringArr_v, $sEncoding, $sFromEncoding );
            }
        }
        return $aStringArr;
    }
    
    /**
     * 明码加密
     * @param string $sMd5 明码md5后的32位字符串，所有前端密码传送约定使用js md5后再传，以免被拦截
     * @return string 返回加密后的密码
     */
    public static function pwdHash( string $sMd5 ): string
    {
        if ( strlen( $sMd5 ) !== 32 )
        {
            return '';
        }
        
        $s_salt = substr( md5( microtime( true ) . '_' . random_int( -999999999, 999999999 ) ), 16 );
        $s_passwd = md5( "fixed_string{$sMd5}{$s_salt}" );
        return $s_salt . substr( $s_passwd, 16 );
    }
    
    /**
     * 密码验证
     * @param string $sMd5 明码md5后的32位字符串，所有前端密码传送约定使用js md5后再传，以免被拦截
     * @param string $sPasswd 密码
     * @return bool
     */
    public static function pwdSign( string $sMd5, string $sPasswd ): bool
    {
        if ( strlen( $sMd5 ) !== 32 )
        {
            return false;
        }
        
        $s_salt = substr( $sPasswd, 0, 16 );
        $s_passwd_tmp = md5( "fixed_string{$sMd5}{$s_salt}" );
        //hash_equals防止时序攻击的字符串比较
        return hash_equals( substr( $sPasswd, 16 ), substr( $s_passwd_tmp, 16 ) );
    }
    
    /**
     * 有时间限制的加密/解密
     * @param string $string 加密/解密内容
     * @param boolean $bEncode true:加密,false:解密,默认true
     * @param string $sKey 加密干扰串,默认内置加密干扰串
     * @param int $iExpiry 有效时间,单位秒,默认不过期
     * @param bool $bRound 是否进行随机，默认相同信息加密后返回的密文一样
     * @return string
     */
    public static function authWithTime( string $sString, bool $bEncode = true, string $sKey = '', int $iExpiry = 0, bool $bRound = false ): string
    {
        if ( $bEncode )
        {
            $iTime = sprintf( '%010d', $iExpiry ? $iExpiry + time() : 0 );
            return self::auth( $iTime . $sString, true, $sKey, $bRound );
        } else
        {
            $s_decode_string = self::auth( $sString, false, $sKey );
            if ( empty( $s_decode_string ) )
            {
                return '';
            }
            
            $i_time = substr( $s_decode_string, 0, 10);
            if ( $i_time > 0 && $i_time < time() )
            {
                return '';
            }
            
            return substr( $s_decode_string, 10 );
        }
    }
    
    /**
     * 加密/解密信息，为了用于url安全传输，加密出来的+替换为-，/替换为_
     * @param string $sString 加密/解密内容
     * @param bool $bEncode true:加密,false:解密,默认true
     * @param string $sKey 加密干扰串,默认内置加密干扰串
     * @param bool $bRound 是否进行随机，默认相同信息加密后返回的密文一样
     * @return string
     */
    public static function auth( string $sString, bool $bEncode = true, string $sKey = '', bool $bRound = false ): string
    {
        if ( $bEncode )
        {
            $sString = self::_auth( $sString, $bEncode, $sKey, $bRound );
            return str_replace( array( '+', '/' ), array( '-', '_' ), $sString );
        } else 
        {
            $sString = str_replace( array( '-', '_' ), array( '+', '/' ), $sString );
            return self::_auth( $sString, $bEncode, $sKey, $bRound );
        }
    }
    
    /**
     * @author discuz (haozi modify)
     * 加密/解密
     * @param string $sString 加密/解密内容
     * @param bool $bEncode true:加密,false:解密,默认true
     * @param string $sKey 加密干扰串,默认内置加密干扰串
     * @param bool $bRound 是否进行随机，默认相同信息加密后返回的密文一样
     * @return string
     */
    private static function _auth( string $sString, bool $bEncode = true, string $sKey = '', bool $bRound = false ): string
    {
        $sKey = $sKey ?: 'wu!_+&^onml#*%)ik{>?l';
        // 动态密匙长度，相同的明文会生成不同密文就是依靠动态密匙
        $i_ckey_length = 4;
        
        // 密匙
        list( $s_keya, $s_keyb ) = str_split( md5( $sKey ), 16 );
        
        // 密匙a会参与加解密
        $s_keya = md5( $s_keya );
        // 密匙b会用来做数据完整性验证
        $s_keyb = md5( $s_keyb );
        // 密匙c用于变化生成的密文
        if ( $bEncode )
        {
            $s_keyc = substr( md5( $bRound ? microtime() : $sKey ), -$i_ckey_length );
        } else 
        {
            $s_keyc = substr( $sString, 0, $i_ckey_length );
        }
        
        // 参与运算的密匙
        $s_cryptkey = $s_keya . md5( $s_keya . $s_keyc );
        $i_key_length = strlen( $s_cryptkey );
        
        // 明文，前10位用来保存时间戳，解密时验证数据有效性，10到26位用来保存$s_keyb(密匙b)，解密时会通过这个密匙验证数据完整性
        // 如果是解码的话，会从第$i_ckey_length位开始，因为密文前$i_ckey_length位保存 动态密匙，以保证解密正确
        if ( $bEncode )
        {
            $sString = substr( md5( $sString . $s_keyb ), 0, 4 ) . $sString;
        } else 
        {
            $sString = base64_decode( substr( $sString, $i_ckey_length ) );
        }
        $i_string_length = strlen( $sString );
        
        $s_result = '';
        $l_box = range( 0, 255 );
        $l_rndkey = array();
        
        // 产生密匙簿
        for ( $i_i = 0; $i_i <= 255; $i_i++ )
        {
            $l_rndkey[$i_i] = ord( $s_cryptkey[$i_i % $i_key_length] );
        }
        
        // 用固定的算法，打乱密匙簿，增加随机性，好像很复杂，实际上对并不会增加密文的强度
        for ( $i_j = $i_i = 0; $i_i <= 255; $i_i++ )
        {
            $i_j = ($i_j + $l_box[$i_i] + $l_rndkey[$i_i]) % 256;
            $i_box_v = $l_box[$i_i];
            $l_box[$i_i] = $l_box[$i_j];
            $l_box[$i_j] = $i_box_v;
        }
        
        // 核心加解密部分
        for ( $i_a = $i_j = $i_i = 0; $i_i < $i_string_length; $i_i++ )
        {
            $i_a = ($i_a + 1) % 256;
            $i_j = ($i_j + $l_box[$i_a]) % 256;
            $i_box_v = $l_box[$i_a];
            $l_box[$i_a] = $l_box[$i_j];
            $l_box[$i_j] = $i_box_v;
            // 从密匙簿得出密匙进行异或，再转成字符
            $s_result .= chr( ord( $sString[$i_i]) ^ ($l_box[($l_box[$i_a] + $l_box[$i_j]) % 256]) );
        }
        
        if ( $bEncode )
        {
            // 把动态密匙保存在密文里，这也是为什么同样的明文，生产不同密文后能解密的原因
            // 因为加密后的密文可能是一些特殊字符，复制过程可能会丢失，所以用base64编码
            return $s_keyc . rtrim( base64_encode( $s_result ), '=' );
        } else
        {
            // substr($s_result, 10, 16) == substr(md5(substr($s_result, 26).$s_keyb), 0, 16) 验证数据完整性
            // 验证数据有效性，请看未加密明文的格式
            $s_check_str = substr( md5( substr( $s_result, 4 ) . $s_keyb ), 0, 4 );
            if ( $s_check_str == substr( $s_result, 0, 4 ) )
            {
                return substr( $s_result, 4 );
            } else
            {
                return '';
            }
        }
    }
    
    /**
     * 汉字转拼音
     * @param string $string 汉字字符串
     * @param bool $upper 是否返回大写
     * @param bool $rfirst 是否返回首字母
     * @return string
     */
    public static function pinYin( string $sString, bool $bUpper = false, bool $bRfirst = false ): string
    {
        UtilCom::import( 'Pinyin' );
        $s_pingyin = $bRfirst ? Pinyin::strToFirstPinyin( $sString, $bUpper ) : Pinyin::strToPinyin( $sString, $bUpper );
        return preg_replace( '/[^!-~]/', '', $s_pingyin );
    }
    
    /**
     * 过虑特殊字符
     * @param string $string 要过虑的字符串
     * @param string $options 选项
     */
    public static function xmlCdata( string $sString, int $iOptions = null ): string
    {
        $sString = preg_replace( "/[^\x{4e00}-\x{9fa5}!-~·-￥\s ]/u", '', $sString );
        if ( $iOptions === LIBXML_NOCDATA )
        {
            if ( strpos( $sString, '<' ) !== false
                || strpos( $sString, '>' ) !== false
                || strpos( $sString, '&' ) !== false
                //|| strpos( $sString, "'" ) !== false
                //|| strpos( $sString, '"' ) !== false
            )
            {
                $sString = "<![CDATA[{$sString}]]>";
            }// else
            //{
                //$string = $string;
            //}
        } else
        {
            $sString = htmlspecialchars( $sString );
        }
        return $sString;
    }
}
