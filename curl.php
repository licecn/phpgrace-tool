<?php
/**
 * curl
 * @link      http://www.phpGrace.com
 * @copyright Copyright (c) 2010-2018 phpGrace.
 * @license   http://www.phpGrace.com/license
 * @package   phpGrace/tools
 * @author    haijun liu mail:5213606@qq.com
 * @version   1.1 Beta
 */
namespace phpGrace\tools;
class curl {
	public  $httpStatus;
	private $curlHndle;
	public  $speed;
	public  $timeOut = 20;
	
	public function __construct(){
		$this->curlHandle = curl_init();
	}
	
	public function get($url){
        curl_setopt($this->curlHandle, CURLOPT_URL            , $url);
        curl_setopt($this->curlHandle, CURLOPT_RETURNTRANSFER , true);
        curl_setopt($this->curlHandle, CURLOPT_SSL_VERIFYPEER , false);
        curl_setopt($this->curlHandle, CURLOPT_SSL_VERIFYHOST , false);
		curl_setopt($this->curlHandle, CURLOPT_ENCODING       , 'gzip,deflate');
		curl_setopt($this->curlHandle, CURLOPT_TIMEOUT        , $this->timeOut);
		$result =  curl_exec($this->curlHandle);
        $this->http_status = curl_getinfo($this->curlHandle);
		$this->speed       = round($this->httpStatus['pretransfer_time']*1000, 2);
        return $result;
	}
	
	public function post($url, $data){
		curl_setopt($this->curlHandle, CURLOPT_POST, 1);
		curl_setopt($this->curlHandle, CURLOPT_POSTFIELDS, $data);
        return $this->get($url);
	}
}