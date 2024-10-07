<?php
/**
 * 目录操作类
 * @link      http://www.phpGrace.com
 * @copyright Copyright (c) 2010-2018 phpGrace.
 * @license   http://www.phpGrace.com/license
 * @package   phpGrace/tools
 * @author    haijun liu mail:5213606@qq.com
 * @version   1.1 Beta
 */
namespace phpGrace\tools;
class dir{

    //获取目录列表
    public function listDir($dir){
        static $fileList = array();
        if(!is_dir($dir)){return null;}
        $list = $this->scanDir($dir);
        foreach($list as $item){
            if($item != '.' && $item != '..'){
                if(is_dir($item)){
                    $fileList['dirList'][] = $item;
                }else{
                    $fileList['fileList'][] = $item;
                }
            }
        }
        return $fileList;
    }

    //创建目录
    public function mkDir($dir){
        if(is_dir($dir)){return true;}
        return mkdir($dir, '0777', true);
    }

    public function scanDir($dir) {
        if(function_exists('scandir')){return scandir($dir);}
        $dh = opendir($dir);
        $arr = array();
        while($file = readdir($dh)) {
            if($file == '.' || $file == '..') continue;
            $arr[] = $file;
        }
        closedir($dh);
        return $arr;
    }

    // 递归删除目录
    public function rmDir($dir, $keepdir = false) {
        // 避免意外删除整站数据
        if(!is_dir($dir) || $dir == '/' || $dir == '../'){return false;}
        $files = $this->scanDir($dir);
        foreach($files as $file) {
            if($file == '.' || $file == '..') continue;
            $filepath = $dir.'/'.$file;
            if(!is_dir($filepath)) {
                try{unlink($filepath);}catch(\Exception $e){}
            }else{
                $this->rmDir($filepath);
            }
        }
        if(!$keepdir){
            try{rmdir($dir);}catch(\Exception $e){}
        }
        return true;
    }

    //重命名
    public function reName($oldName, $newName){
        @rename($oldName, $newName);
    }

    //复制
    public function copyDir($src, $dst){
        $dir = opendir($src);
        $this->mkdir($dst);
        while(false !== ($file = readdir($dir))){
            if(( $file != '.' ) && ( $file != '..' )) {
                if ( is_dir($src . '/' . $file) ) {
                    $this->copyDir($src . '/' . $file,$dst . '/' . $file); continue;
                }else {
                    copy($src . '/' . $file,$dst . '/' . $file);
                }
            }
        }
        closedir($dir);
    }
}