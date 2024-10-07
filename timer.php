<?php
/**
 * 日期时间操作类
 * @link      http://www.phpGrace.com
 * @copyright Copyright (c) 2010-2018 phpGrace.
 * @license   http://www.phpGrace.com/license
 * @package   phpGrace/tools
 * @author    haijun liu mail:5213606@qq.com
 * @version   1.1 Beta
 */
namespace phpGrace\tools;
class timer{
	
	//当前年
	public function currentYear(){
		return date("Y");
	}
	
	//当前月
	public function currentMonth(){
		return date("m");
	}
	
	//当前日期
	public function currentDay(){
		return date("d");
	}
	
	//当前时
	public function currentHour(){
		return date("H");
	}
	
	//当前分
	public function currentMin(){
		return date("i");
	}
	
	//当前秒
	public function currentSecond(){
		return date("s");
	}
	
	//当前日期 按照指定格式及指定时间戳
	public function dateTime($format = "Y-m-d H:i:s", $currentTime = null){
		if($currentTime == null){return date($format);}
		return date($format, $currentTime);
	}
	
	//日期时间转换时间戳
	public function timeStamp($timer = null){
		if($timer == null){$timer = date("m/d/Y H:i:s");}
		$mode = '/^(\d{4,4})\-(\d{2,2})\-(\d{2,2}) (\d{2,2}):(\d{2,2}):(\d{2,2})$/Uis';
		$res  = preg_match($mode, $timer, $arr);
		$timerPre = array();
		if(!$res){
			$mode = '/^(\d{2,2})\/(\d{2,2})\/(\d{4,4}) (\d{2,2}):(\d{2,2}):(\d{2,2})$/Uis';
			$res  = preg_match($mode, $timer, $arr);
			if(!$res){exit('日期格式错误');}
			$timerPre = array($arr[1], $arr[2], $arr[3], $arr[4], $arr[5], $arr[6]);
		}else{
			$timerPre = array($arr[2], $arr[3], $arr[1], $arr[4], $arr[5], $arr[6]);
		}
		return mktime($timerPre[3], $timerPre[4], $timerPre[5], $timerPre[0], $timerPre[1], $timerPre[2]);
	}
	
	//日期与日期间的差值
	public function DValue($timer1, $timer2){
		return $this->timeStamp($timer1) - $this->timeStamp($timer2);
	}
	
	//计算过去时间并格式化
	public function fromTime($time){
	    $timer = time() - $time;
	    if($timer < 180){
	        return '刚刚';
	    }elseif($timer >= 180 && $timer < 3600){
	        return floor($timer / 60).'分钟前';
	    }elseif($timer >= 3600 && $timer < 86400){
	        return floor($timer / 3600).'小时前';
	    }elseif($timer >= 86400 && $timer < 2592000){
	        return floor($timer / 86400).'天前';
	    }else{
	        return date("Y-m-d H:i", $time);
	    }
	}
}
