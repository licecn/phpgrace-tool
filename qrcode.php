<?php
/**
 * 二维码生成类
 * @link      http://www.phpGrace.com
 * @copyright Copyright (c) 2010-2015 phpGrace.
 * @license   http://www.phpGrace.com/license
 * @package   phpGrace/tool
 * @author    haijun liu mail:5213606@qq.com
 * @version   1.1 Beta
 */
namespace phpGrace\tools;
class qrcode{
	
	public static $includeRec = 0;
	
	public static function draw($data, $fileName, $size = 7, $padding = 1){
		if(self::$includeRec < 1){
			include_once 'phpqrcode/qrlib.php';
		}
		\QRcode::png($data, $fileName, QR_ECLEVEL_L, $size, $padding);
		return $fileName;
	}
}