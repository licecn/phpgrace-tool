<?php
/**
 * 服务器信息类
 * @link      http://www.phpGrace.com
 * @copyright Copyright (c) 2010-2018 phpWit.
 * @license   http://www.phpGrace.com/license
 * @package   phpGrace/tool
 * @author    haijun liu mail:5213606@qq.com
 * @version   1.1 Beta
 */
namespace phpGrace\tools;
class server{
 	public static function info(){
		//操作系统信息
		$arr[0] =  php_uname();
		//服务器CPU数量
		$arr[1] = PHP_VERSION;
		//服务器默认时区
		$arr[2] = date_default_timezone_get().' | '.date('Y-m-d H:i:s');
		//服务器默认时区
		$arr[3] = ini_get('upload_max_filesize');
		//最大运行时间
		$arr[4] = ini_get('max_execution_time');
		//php运行模式
		$arr[5] = php_sapi_name();
		//gd库信息
		if(function_exists("gd_info")){ 
			$gd = gd_info();
			$arr[6] = $gd['GD Version'];
		}else{
			$arr[6] = "未知";
		}
		return $arr;
	}
 }
