<?php

/**
 * 
 * 验证工具类
 *
 */
class UtilValid
{
    /**
     * 数据验证
     * @param array $mData 要验证的数据信息
     * @param array $lValids 验证规则
     * @example
     * $mData = array(
     *     'field1'    => 'value1',
     *     'field2'    => '222@qq.com',
     *     'field3'    => '333@qq.com',
     *     'field4'    => '444@qq.com',
     *     'field5'    => '555@qq.com',
     * )
     * $lValids = array(
     *   //验证字段名     =>  验证因子
     *     'field1',//默认验证类型为string
     *     'field2'    => 'email',//验证Email地址
     *     'field3'    => array( 'type' => 'string', 'min' => 7 ),//验证最少长度7个字符
     *     'field4'    => array( 'email', array( 'type' => 'string', 'max' => 10 ) ),//验证Email地址,并且最大长度10个字符(多重验证)
     *     'field5'    => array( array( 'type' => 'email' ), array( 'type' => 'string', 'min' => 7, 'max' => 10 ) ),//验证Email地址,并且最少长度7个字符,最大长度10个字符(多重验证)
     * )
     * list( $mData, $error, $l_errors ) = \UtilsValidations::validate( $mData, $lValids );
     * 
     * 验证因子参数介绍
     * array(
     *     'type'   => 'string',         string,可选,默认string,验证类型
     *     'min'    => 3,                int,可选,默认无,最小值(视type决定,如string类型时为最小长度,number类型时为最小数值)
     *     'max'    => 10,               int,可选,默认无,最大值(视type决定,如string类型时为最大长度,number类型时为最大数值)
     *     'list'   => array(),          array,可选,默认无,列表选项值(in类型为选项值,ex类型为排除值),
     *     'strict' => false             bool,可选,默认false,是否严格验证,主要用于in|ex类型,
     *     'regexp' => regexp            regexp,可选,正则表达式主要用于regexp|email|mobile类型,
     *     'null'   => false             bool,可选,默认false,数据为null时是否可以跳过验证,用于所有类型,
     *     'blank'  => false             bool,可选,默认false,数据为空字符串时是否可以跳过验证,用于所有类型,
     *     'empty'  => false             bool,可选,默认false,数据为null或空字符串时是否可以跳过验证,用于所有类型,
     *     'default'=> mixed             mixed,可选,默认无,验证失败或跳过验证时默认值
     *     'untrim' => false             bool,可选,默认false,是否不删除首尾空白
     * )
     * @return array array( $mData, $error, $l_errors ) 返回验证通过的数据和错误信息,没有错误时$l_errors为空数组
     */
    public static function validate( $mData, array $lValids ): array
    {
        if ( !is_array( $mData ) )
        {
            $a_error = array(
                'field'       => 'g_all',
                //'value'       => null,//用户输入什么就输出什么的时候有跨站攻击危险，注释掉
                'message'     => '没有获取到要检测的参数信息',
                //'type'        => 'g_all',
            );
            return array( array(), $a_error, array( $a_error ) );
        }
        
        $l_errors = array();//错误信息
        $l_return_datas = array();//验证通过的数据
        $s_message = '参数校验失败';
        
        foreach ( $lValids as $s_field => $l_valuds )
        {
            if ( false == isset( $l_valuds[0] ) )
            {
                $l_valuds = array( $l_valuds );
            }
            
            foreach( $l_valuds as $a_valud )
            {
                if ( $a_valud['type'] == 'default' )
                {
                    $mData[$s_field] = $a_valud['default'];
                }
                
                if ( false == isset( $mData[$s_field] )
                    && (false === empty( $a_valud['null'] ) || false === empty( $a_valud['empty'] ))
                )
                {//字段不存在时可跳过验证
                    if ( array_key_exists( 'default', $a_valud ) )
                    {
                        $l_return_datas[$s_field] = $a_valud['default'];//默认值
                    }
                    continue;
                }
                
                //去掉前后空白
                if ( isset( $mData[$s_field] ) )
                {
                    if ( is_string( $mData[$s_field] ) && empty( $a_valud['untrim'] ) )
                    {
                        $mData[$s_field] = trim( $mData[$s_field] );
                    }
                } else 
                {
                    $mData[$s_field] = null;
                }
                
                if ( $mData[$s_field] === ""
                    && (false === empty( $a_valud['blank'] ) || false === empty( $a_valud['empty'] ))
                )
                {//字段空白串时可跳过验证
                    if( array_key_exists( 'default', $a_valud ) )
                    {
                        $l_return_datas[$s_field] = $a_valud['default'];//默认值
                    } else 
                    {
                        $l_return_datas[$s_field] = '';
                    }
                    continue;
                }
                
                if ( !empty( $a_valud['decode'] ) && isset( $mData[$s_field] ) )
                {//解码加密数据
                    $mData[$s_field] = \UtilString::auth( $mData[$s_field], false );
                }
                
                //验证
                $s_fun = "type{$a_valud['type']}";
                if ( !isset( $mData[$s_field] ) || true !== self::$s_fun( $mData[$s_field], $a_valud ) )
                {//验证失败
                    if ( empty( $a_valud['skip'] ) )
                    {
                        $l_errors[$s_field] = array(
                            'field'       => $s_field,
                            //'value'       => $mData[$s_field],//用户输入什么就输出什么的时候有跨站攻击危险，注释掉
                            'message'     => empty( $a_valud['message'] ) ? "{$s_field}:{$s_message}" : $a_valud['message'],
                            //'type'        => $a_valud['type'],
                        );
                    }
                    
                    if ( array_key_exists( 'default', $a_valud ) )
                    {
                        $l_return_datas[$s_field] = $a_valud['default'];//默认值
                    }
                } else 
                {//验证通过
                    $l_return_datas[$s_field] = $mData[$s_field];
                }
            }
        }
        return array( $l_return_datas, current( $l_errors ), $l_errors );
    }
    
    /**
     * 长度验证方法
     * @param mixed $mData 要验证的数据
     * @param array $aConf 验证配置
     * @return bool
     */
    public static function typeLength( $mData, array $aConf = array() ): bool
    {
        $aConf['min'] = $aConf['max'] = (int)$aConf['length'];
        return self::typeString( $mData, $aConf );
    }
    
    /**
     * 长度验证方法
     * @param mixed $mData 要验证的数据
     * @param array $aConf 验证配置
     */
    public static function typeString( $mData, array $aConf = array() ): bool
    {
        if ( is_numeric( $mData ) )
        {
            $mData = (string)$mData;
        }
        
        if ( false == is_string( $mData ) )
        {
            return false;
        }
        
        $i_str_len = isset( $aConf['encoding'] ) ? mb_strlen( $mData, $aConf['encoding'] ) : strlen( $mData );
        if ( isset( $aConf['min'] ) && $i_str_len < $aConf['min'] )
        {
            return false;
        } elseif ( isset( $aConf['max'] ) && $i_str_len > $aConf['max'] )
        {
            return false;
        }
        
        return true;
    }
    
    /**
     * 长度验证方法
     * @param mixed $mData 要验证的数据
     * @param array $aConf 验证配置
     */
    public static function typeStringUtf8( $mData, array $aConf = array() ): bool
    {
        $aConf['encoding'] = 'utf-8';
        return self::typeString( $mData, $aConf );
    }
    
    /**
     * 英文数字常见字符串验证方法
     * @param mixed $mData 要验证的数据
     * @param array $aConf 验证配置
     */
    public static function typeStringW( $mData, array $aConf = array() ): bool
    {
        if ( false == self::typeString( $mData, $aConf ) )
        {
            return false;
        }
        
        return preg_match( '/^[\w-]*$/', $mData );
    }
    
    /**
     * ascii字符串验证方法
     * @param mixed $mData 要验证的数据
     * @param array $aConf 验证配置
     */
    public static function typeStringA( $mData, array $aConf = array() ): bool
    {
        if ( false == self::typeString( $mData, $aConf ) )
        {
            return false;
        }
        
        return preg_match( '/^[ -~]*$/', $mData );
    }
    
    /**
     * 正则表达式验证
     * @param mixed $mData 要验证的数据
     * @param array $aConf 验证配置
     */
    public static function typeRegexp( $mData, array $aConf = array() ): bool
    {
        return preg_match( $aConf['regexp'], $mData );
    }
    
    /**
     * 包含验证方法,验证的数据必需包含在给定的列表中
     * @param mixed $mData 要验证的数据
     * @param array $aConf 验证配置,例:
     *     array(
     *         'list' => array( ... ),//给定的列表
     *  )
     */
    public static function typeIn( $mData, array $aConf ): bool
    {
        return in_array( $mData, $aConf['list'], true );
    }
    
    /**
     * 包含验证方法,验证的数字必需包含在给定的列表中
     * @param mixed $mData 要验证的数据
     * @param array $aConf 验证配置,例:
     *     array(
     *         'list' => array( ... ),//给定的列表必须是int类型
     *  )
     */
    public static function typeInInt( $mData, array $aConf ): bool
    {
        if ( true !== self::typeInt( $mData ) )
        {
            return false;
        }
        return in_array( (int)$mData, $aConf['list'], true );
    }
    
    /**
     * 排除验证方法,验证的数据必需排除在给定的列表外
     * @param mixed $mData 要验证的数据
     * @param array $aConf 验证配置,例:
     *     array(
     *         'list' => array( ... ),//给定的列表
     *         'strict' => true,//严格检查数据类型
     *  )
     */
    public static function typeEx( $mData, array $aConf ): bool
    {
        return false == self::typeIn( $mData, $aConf );
    }
    
    /**
     * Email地址验证
     * @param mixed $mData 要验证的数据
     * @param array $aConf 验证配置
     */
    public static function typeEmail( $mData, array $aConf = array() ): bool
    {
        return preg_match( $aConf['regexp'] ?? '/^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/', $mData );
    }
    
    /**
     * mobile验证
     * @param mixed $mData 要验证的数据
     * @param array $aConf 验证配置
     */
    public static function typeMobile( $mData, array $aConf = array() ): bool
    {
        return preg_match( $aConf['regexp'] ?? '/^1[3-9]\d{9}$/' , $mData );
    }
    
    /**
     * 身份证验证
     * @param mixed $mData 要验证的数据
     * @param array $aConf 验证配置
     */
    public static function typeIdnumber( $mData, array $aConf = array() ): bool
    {
        $b_is_15 = false;//是否是15位长度身份证
        if ( preg_match( '/^\d{17}[xX\d]$/', $mData ) )
        {//无操作
        } elseif ( preg_match( '/^\d{15}$/', $mData ) )
        {//设置为15位身份证
            $b_is_15 = true;
        } else
        {
            return false;
        }
        
        /*地区检查-开始*/
        $l_areas = array(
            11 => "北京", 12 => "天津", 13 => "河北", 14 => "山西", 15 => "内蒙古",
            21 => "辽宁", 22 => "吉林", 23 => "黑龙江", 31 => "上海", 32 => "江苏",
            33 => "浙江", 34 => "安徽", 35 => "福建", 36 => "江西", 37 => "山东",
            41 => "河南", 42 => "湖北", 43 => "湖南", 44 => "广东", 45 => "广西",
            46 => "海南", 50 => "重庆", 51 => "四川", 52 => "贵州", 53 => "云南",
            54 => "西藏", 61 => "陕西", 62 => "甘肃", 63 => "青海", 64 => "宁夏",
            65 => "新疆", 71 => "台湾", 81 => "香港", 82 => "澳门", 91 => "国外",
        );
        $i_area_key = substr( $mData, 0, 2 );
        if ( false == isset( $l_areas[$i_area_key] ) )
        {
            return false;
        }
        /*地区检查-结束*/
        
        /*日期检查-开始*/
        $i_sub_len = $b_is_15 ? 2 : 4;
        $i_year = substr( $mData, 6, $i_sub_len );
        if ( $b_is_15 )
        {
            $i_year = "19{$i_year}";
        }
        $i_month = substr( $mData, 6 + $i_sub_len, 2 );
        $i_day = substr( $mData, 6 + $i_sub_len + 2, 2 );
        if ( $i_year < 1900 )
        {
            return false;
        } elseif ( $i_month > 12 || $i_month < 1 )
        {
            return false;
        } elseif ( $i_day < 1 ) 
        {
            return false;
        } else 
        {
            $a_days = array(
                '01'       => '31',
                '02'       => '29',
                '03'       => '31',
                '04'       => '30',
                '05'       => '31',
                '06'       => '30',
                '07'       => '31',
                '08'       => '31',
                '09'       => '30',
                '10'       => '31',
                '11'       => '30',
                '12'       => '31',
            );
            if ( $i_day > $a_days[$i_month] )
            {
                return false;
            }
        }
        /*日期检查-结束*/
        
        if ( $b_is_15 )
        {//15位没有校验位不用检查最后一位校验位
            return true;
        }
        
        $l_wi = array( 7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2, 1 );
        $i_sum = 0;
        for ( $i = 0; $i < 17; $i++ )
        {
            $i_sum += $mData{$i} * $l_wi[$i];
        }
        
        if ( $mData{17} == 'X' || $mData{17} == 'x' )
        {
            $i_sum += 10 * $l_wi[17];
        } else
        {
            $i_sum += $mData{17} * $l_wi[17];
        }
        
        if ( ($i_sum % 11) == 1 )
        {
            return true;
        } else
        {
            return false;
        }
    }
    
    /**
     * IP地址验证
     * @param mixed $mData 要验证的数据
     * @param array $aConf 验证配置
     */
    public static function typeIp( $mData, array $aConf = array() ): bool
    {
        if ( empty( $mData ) )
        {
            return false;
        }
        
        return $mData === long2ip( ip2long( $mData ) );
    }
    
    /**
     * 整数类型验证
     * @param mixed $mData 要验证的数据
     * @param array $aConf 验证配置
     */
    public static function typeInt( $mData, array $aConf = array() ): bool
    {
        return strpos( $mData, '.' ) === false && self::typeNumber( $mData, $aConf );
    }
    
    /**
     * 整数类型验证
     * @param mixed $mData 要验证的数据
     * @param array $aConf 验证配置
     */
    public static function typeIntArray( $mData, array $aConf = array() ): bool
    {
        $aConf['child_type'] = 'int';
        $aConf['child_conf'] = $aConf['int_conf'] ?? array();
        return self::typeArrayList( $mData, $aConf );
    }
    
    /**
     * 整数类型验证
     * @param mixed $mData 要验证的数据
     * @param array $aConf 验证配置
     */
    public static function typeIntList( $mData, array $aConf = array() ): bool
    {
        $aConf['child_type'] = 'int';
        $aConf['child_conf'] = $aConf['int_conf'] ?? array();
        return self::typeStringList( $mData, $aConf );
    }
    
    /**
     * 浮点数类型验证
     * @param mixed $mData 要验证的数据
     * @param array $aConf 验证配置
     */
    public static function typeFloat( $mData, array $aConf = array() ): bool
    {
        return self::typeNumber( $mData, $aConf );
    }
    
    /**
     * 金额类型验证
     * @param mixed $mData 要验证的数据
     * @param array $aConf 验证配置
     */
    public static function typeMoney( $mData, array $aConf = array() ): bool
    {
        $aConf['decimals'] = 2;
        return self::typeNumber( $mData, $aConf );
    }
    
    /**
     * 数值类型验证
     * @param mixed $mData 要验证的数据
     * @param array $aConf 验证配置
     */
    public static function typeNumber( $mData, array $aConf = array() ): bool
    {
        if ( false == is_numeric( $mData ) )
        {
            return false;
        }
        
        if ( strpos( $mData, '.' ) )
        {//有小数点时判断
            if ( isset( $aConf['decimals'] ) )
            {//判断小数点位数
                $i_multiple = 1 . substr( '0000000000', 0, $aConf['decimals'] );
                $s_data_str = (string)($mData * $i_multiple);
                $i_data_int = (int)$s_data_str;
                if ( (string)$i_data_int !== $s_data_str )
                {//没有全等，小数点数位不对
                    return false;
                }
            }
            
            if ( isset( $aConf['max'] ) || isset( $aConf['min'] ) )
            {
                list( $i_int, $i_dec ) = explode( '.', $mData );
                $i_multiple = 1 . substr( '0000000000', 0, $i_dec );
                $i_data = (int)$mData * $i_multiple;
                
                if ( isset( $aConf['min'] ) )
                {
                    $i_min = (int)$aConf['min'] * $i_multiple;
                    if ( $i_data < $i_min )
                    {
                        return false;
                    }
                }
                
                if ( isset( $aConf['max'] ) )
                {
                    $i_max = (int)$aConf['max'] * $i_multiple;
                    if ( $i_data > $i_max )
                    {
                        return false;
                    }
                }
            }
        } else 
        {//没有小数点时判断
            $i_data = (int)$mData;
            if ( isset( $aConf['min'] ) && (int)$mData < (int)$aConf['min'] )
            {
                return false;
            } elseif ( isset( $aConf['max'] ) && (int)$mData > (int)$aConf['max'] )
            {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * 时间类型验证
     * @param mixed $mData 要验证的数据
     * @param array $aConf 验证配置
     */
    public static function typeTime( $mData, array $aConf = array() ): bool
    {
        if ( false == preg_match( '/^\d{1,2}:\d{1,2}:\d{1,2}$/', (string)$mData ) )
        {
            return false;
        }
        
        $i_time = strtotime( "1970-01-01 {$mData}" );
        if ( $i_time === false)
        {
            return false;
        }
        
        if ( isset( $aConf['min'] ) && $i_time < strtotime( "1970-01-01 {$aConf['min']}" ) )
        {
            return false;
        } elseif ( isset( $aConf['max'] ) && $i_time > strtotime( "1970-01-01 {$aConf['max']}" ) )
        {
            return false;
        }
        
        return true;
    }
    
    /**
     * 时间类型验证(小时数最大999)
     * @param mixed $mData 要验证的数据
     * @param array $aConf 验证配置
     */
    public static function typeTime2( $mData, array $aConf = array() ): bool
    {
        $a_time2_conf = array( '_' => true );
        $i_time = Field::typeTime2( $mData, $a_time2_conf );
        if ( $i_time === 0 || $i_time === false )
        {
            return false;
        }
        
        if ( isset( $aConf['min'] ) )
        {
            $i_min = Field::typeTime2( $aConf['min'], $a_time2_conf );
            if ( $i_time < $i_min )
            {
                return false;
            }
        }
        
        if ( isset( $aConf['max'] ) )
        {
            $i_max = Field::typeTime2( $aConf['max'], $a_time2_conf );
            if ( $i_time > $i_max )
            {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * 时间类型验证
     * @param mixed $mData 要验证的数据
     * @param array $aConf 验证配置
     */
    public static function typeDaytime( $mData, array $aConf = array() ): bool
    {
        $a_time2_conf = array( '_' => true );
        $i_time = \Field::typeDaytime( $mData, $a_time2_conf );
        if ( $i_time === 0 || $i_time === false )
        {
            return false;
        }
        
        if ( isset( $aConf['min'] ) )
        {
            $i_min = Field::typeDaytime( $aConf['min'], $a_time2_conf );
            if ( $i_time < $i_min )
            {
                return false;
            }
        }
        
        if ( isset( $aConf['max'] ) )
        {
            $i_max = Field::typeDaytime( $aConf['max'], $a_time2_conf );
            if ( $i_time > $i_max )
            {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * 时间类型验证
     * @param mixed $mData 要验证的数据
     * @param array $aConf 验证配置
     */
    public static function typeDate( $mData, array $aConf = array() ): bool
    {
        $i_time = is_numeric( $mData ) ? $mData : strtotime( $mData );
        if ( $i_time === false )
        {
            return false;
        }
        
        if ( isset( $aConf['min'] ) )
        {
            $i_min = is_numeric( $aConf['min'] ) ? $aConf['min'] : strtotime( $aConf['min'] );
            if ( $i_time < $i_min )
            {
                return false;
            }
        }
        
        if ( isset( $aConf['max'] ) )
        {
            $i_max = is_numeric( $aConf['max'] ) ? $aConf['max'] : strtotime( $aConf['max'] );
            if ( $i_time > $i_max )
            {
                return false;
            }
        }
        
        return true;
    }

    /**
     * 时间类型验证
     * @param mixed $mData 要验证的数据
     * @param array $aConf 验证配置
     */
    public static function typeDatetime( $mData, array $aConf = array() ): bool
    {
        $i_time = is_numeric( $mData ) ? $mData : strtotime( $mData );
        if ( $i_time === false )
        {
            return false;
        }
        
        if ( isset( $aConf['min'] ) )
        {
            $i_min = is_numeric( $aConf['min'] ) ? $aConf['min'] : strtotime( $aConf['min'] );
            if ( $i_time < $i_min )
            {
                return false;
            }
        }
        
        if ( isset( $aConf['max'] ) )
        {
            $i_max = is_numeric( $aConf['max'] ) ? $aConf['max'] : strtotime( $aConf['max'] );
            if ( $i_time > $i_max )
            {
                return false;
            }
        }
        
        return true;
    }

    /**
     * 自定义方法类型验证
     * @param mixed $mData 要验证的数据
     * @param array $aConf 验证配置
     */
    public static function typeMethod( $mData, array $aConf ): bool
    {
        return call_user_func( $aConf['method'], $mData, $aConf );
    }
    
    /**
     * 数组类型验证
     * @param mixed $mData 要验证的数据
     * @param array $aConf 验证配置
     */
    public static function typeArray( $mData, array $aConf ): bool
    {
        if ( true !== is_array( $mData ) )
        {
            return false;
        }
        
        $i_length = count( $mData );
        if ( isset( $aConf['length'] ) && $i_length != $aConf['length'] )
        {
            return false;
        } elseif ( isset( $aConf['min'] ) && $aConf['min'] > $i_length )
        {
            return false;
        } elseif ( isset( $aConf['max'] ) && $aConf['max'] < $i_length )
        {
            return false;
        }
        
        return true;
    }
    
    /**
     * 数组各类型验证
     * @param mixed $mData 要验证的数据
     * @param array $aConf 验证配置
     */
    public static function typeArrayList( $mData, array $aConf = array() ): bool
    {
        $b_result = self::typeArray( $mData, $aConf );
        if ( true !== $b_result )
        {
            return $b_result;
        }
        
        $s_fun_name = "type{$aConf['child_type']}";
        $a_child_conf = $aConf['child_conf'] ?? array();
        foreach ( $mData as $m_data_v )
        {
            if ( !empty( $a_child_conf['decode'] ) && $m_data_v !== null )
            {//解码加密数据
                $m_data_v = \UtilString::auth( $m_data_v, false );
            }
            if ( true !== self::$s_fun_name( $m_data_v, $a_child_conf ) )
            {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * 字符串各类型验证
     * @param mixed $mData 要验证的数据
     * @param array $aConf 验证配置
     */
    public static function typeStringList( $mData, array $aConf = array() ): bool
    {
        if ( true !== is_string( $mData ) )
        {
            return false;
        }
        
        $l_datas = explode( $aConf['splitter'] ?? ',', $mData );
        return self::typeArrayList( $l_datas, $aConf );
    }
    
    /**
     * 多个数字验证
     * @param mixed $mData 要验证的数据
     * @param array $aConf 验证配置
     */
    public static function typeNumberList( $mData, array $aConf = array() ): bool
    {
        if ( true !== is_string( $mData ) )
        {
            return false;
        }
        
        $l_datas = explode( $aConf['splitter'] ?? ',', $mData );
        $aConf['child_type'] = 'number';
        return self::typeArrayList( $l_datas, $aConf );
    }
    
    /**
     * @author ak
     * 默认值
     * @param mixed $mData 要验证的数据
     * @param array $aConf 验证配置
     */
    public static function typeDefault( $mData, array $aConf = array() ): bool
    {
        return true;
    }
    
    /**
     * @author ak
     * 按微博长度验证
     * @param mixed $mData 要验证的数据
     * @param array $aConf 验证配置
     */
    /*public static function typeWeiboString( $mData, array $aConf )
    {
        $len = \UtilString::weiboLen( $mData );
        if( isset( $aConf['min'] ) && $len < $aConf['min'] )
        {
            return false;
        } else if( isset( $aConf['max'] ) && $len > $aConf['max'] )
        {
            return false;
        } else
        {
            return true;
        }
    }*/
    
    /**
     * @author ak
     * 网址验证
     * @param mixed $mData 要验证的数据
     * @param array $aConf 验证配置
     */
    public static function typeUrl( $mData, array $aConf = array() ): bool
    {
        if ( true !== is_string( $mData ) )
        {
            return false;
        } elseif ( false == preg_match( '/^[!-~]+$/', $mData ) )
        {
            return false;
        }
        
        $i_length = strlen( $mData );
        if ( isset( $aConf['min'] ) && $i_length < $aConf['min'] )
        {
            return false;
        } elseif ( isset( $aConf['max'] ) && $i_length > $aConf['max'] )
        {
            return false;
        }
        
        
        $a_url_info = parse_url( $mData );
        if ( false === empty( $a_url_info['host'] ) )
        {
            return false;
        } elseif ( 0 !== stripos( $a_url_info['scheme'], 'http' ) )
        {
            return false;
        }
        
        return true;
    }
    
    /**
     * @author ak
     * boolean值验证
     * @param mixed $mData 要验证的数据
     * @param array $aConf 验证配置
     */
    public static function typeBool( $mData, array $aConf = array() ): bool
    {
        if ( empty( $mData ) )
        {
            return false;
        } elseif ( $mData === 'false' || $mData === 'no' )
        {
            return false;
        }
        
        return true;
    }
    
    /**
     * @author ak
     * 坐标值验证
     * @param mixed $mData 要验证的数据
     * @param array $aConf 验证配置
     */
    public static function typeLnglat( $mData, array $aConf = array() ): bool
    {
        if ( true !== is_string( $mData ) )
        {
            return false;
        }
        
        return preg_match( '/^[\d\.]+,\s?[\d\.]+$/i', $mData );
    }
    
    /**
     * @author ak
     * 域名验证
     * @param mixed $mData 要验证的数据
     * @param array $aConf 验证配置
     */
    public static function typeHost( $mData, array $aConf = array() ): bool
    {
        if ( !is_string( $mData ) )
        {
            return false;
        } elseif ( !preg_match( '/^[a-z0-9][a-z0-9\.\-]+[a-z0-9]?$/', $mData ) )
        {
            return false;
        }
        
        return true;
    }
    
    /**
     * @author ak
     * 等值验证
     * @param mixed $mData 要验证的数据
     * @param array $aConf 验证配置
     */
    public static function typeEq( $mData, array $aConf = array() ): bool
    {
        if ( true !== is_string( $mData ) || empty( $mData ) )
        {
            return false;
        }
        
        return hash_equals( $aConf['eq'], $mData );
    }
}
