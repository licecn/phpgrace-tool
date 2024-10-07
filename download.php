<?php
/**
 * 文件下载类
 * @link      http://www.phpgrace.com
 * @copyright Copyright (c) 2010-2015 phpWit.
 * @license   http://www.phpgrace.com/license
 * @package   phpWit/tool
 * @author    haijun liu mail:5213606@qq.com
 * @version   1.1 Beta
 */
namespace phpGrace\tools;
class download {
    public static function download($filename, $downLoadName = NULL) {
        if($downLoadName == NULL){$downLoadName = $filename;}
        if (strpos($filename, '.') === false){return false;}
        $mime   = 'application/octet-stream';
        $handle = fopen($filename, 'r');
        $data   = fread($handle, filesize($filename));
        fclose($handle);
        if (strpos($_SERVER['HTTP_USER_AGENT'], "MSIE") !== FALSE){
            header('Content-Type: "'.$mime.'"');
            header('Content-Disposition: attachment; filename="'.$downLoadName.'"');
            header('Expires: 0');
            header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
            header("Content-Transfer-Encoding: binary");
            header('Pragma: public');
            header("Content-Length: ".strlen($data));
        }else{
            header('Content-Type: "'.$mime.'"');
            header('Content-Disposition: attachment; filename="'.$downLoadName.'"');
            header("Content-Transfer-Encoding: binary");
            header('Expires: 0');
            header('Pragma: no-cache');
            header("Content-Length: ".strlen($data));
        }
        exit($data);
    }
}