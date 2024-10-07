<?php
/**
 * 分类树处理类
 * @link      http://www.phpGrace.com
 * @copyright Copyright (c) 2010-2015 phpGrace.
 * @license   http://www.phpGrace.com/license
 * @package   phpGrace/tool
 * @author    haijun liu mail:5213606@qq.com
 * @version   1.1 Beta
 */
namespace phpGrace\tools;
class tree {
	public $m;	
	private $nodes;
	public $currentId = null;
	public function __construct($tableName, $gets = array()){
		$this->m = db($tableName); $this->gets = $gets;
	}
	//输出表格类型的树状数据
	public function showTableTree($parentId, $level = 0){
		$nodes = $this->getSons($parentId);
		if(!empty($nodes)){
			foreach($nodes as $k => $v){
				echo "
<tr id=\"grace-item-{$v[0]}\">
	<td>".str_repeat('&nbsp;&nbsp;&nbsp;&nbsp;', $level)."|_ ID : {$v[0]}</td>
	<td>{$k}</td>
	<td>{$v[1]}</td>
	<td>{$v[2]}</td>
	<td>{$v[3]}</td>
	<td>
		<a href=\"".u(PG_C, 'edit', implode('/', $this->gets)).'/'.$v[0]."\">
        	<i class=\"layui-icon\">&#xe640;</i> 编辑
    	</a>
		<a href=\"javascript:graceDelete('".u(PG_C, 'delete', $this->gets[0].'/'.$v[0])."', '#grace-item-{$v[0]}');\">
        	<i class=\"layui-icon\">&#xe640;</i> 删除
        </a>
	</td>
</tr>";
			$this->showTableTree($v[0], $level+1);
			}
		}
	}
	
	//输出option类型的树状数据
	public function showOptionTree($parentId, $level = 0){
		$nodes = $this->getSons($parentId);
		if(!empty($nodes)){
			foreach($nodes as $k => $v){
				if($this->currentId == $v[0]){$sed = ' selected="selected"';}else{$sed = '';}
				echo "<option value=\"{$v[0]}\"{$sed}>".str_repeat('&nbsp;&nbsp;&nbsp;&nbsp;', $level)."|_ <strong>{$v[1]}</strong></option>";
				$this->showOptionTree($v[0], $level+1);
			}
		}
	}
	
	//删除分类
	public function delete($id){
		//取得被删除类别的左右值,检测是否有子类,如果有就一起删除
		$node =$this->getNodeById($id);
		//执行删除
		if($this->m->where('cate_left >= ? and cate_right <= ?', array($node['cate_left'], $node['cate_right']))->delete()){
		    $value= ($node['cate_right'] - $node['cate_left'] + 1) * -1;
		    //更新左右值
			$this->m->where('cate_left > ?', $node['cate_left'])->field('cate_left', $value);
			$this->m->where('cate_right > ?', $node['cate_right'])->field('cate_right', $value);
		}
	}
	
	//查询某一分类下的子分类(直接归属)
	public function getSons($parentId){
		$this->nodes = array();
		//查询父类信息
		$parentNode = $this->getNodeById($parentId);
		if(empty($parentNode)){return null;}
		//
		$firstNode  = $this->m->where('cate_left = ?', $parentNode['cate_left']+1)->fetch();
		if(empty($firstNode)){return null;}
		$this->nodes[$firstNode['cate_order']] = array($firstNode['cate_id'], $firstNode['cate_name'], $firstNode['cate_left'], $firstNode['cate_right']);
		$this->getNextNodes($firstNode['cate_right'] + 1);
		ksort($this->nodes);
		return $this->nodes;
	}
	
	//查找第一节点后的直属节点
	private function getNextNodes($left){
		$thisNode   = $this->m->where('cate_left = ?', $left)->fetch();
		if(empty($thisNode)){return null;}
		$this->nodes[$thisNode['cate_order']] = array($thisNode['cate_id'], $thisNode['cate_name'], $thisNode['cate_left'], $thisNode['cate_right']);
		$this->getNextNodes($thisNode['cate_right'] + 1);
	}
	
	/*
	 * 增加节点
	 * $type 1: 代表增加子节点   2:增加同级节点
	*/
	public function addNode($parentId, $name, $desc, $order){
		$parentId    = intval($parentId);
		if($parentId >= 1){
			$currentNode = $this->getNodeById($parentId);
			if(empty($currentNode)) {throw new witException('不存在的父类');}
			//新节点的左值为父节点的右值
			$leftNode    = $currentNode['cate_right'];
			//新节点的右值为父节点的右值+1
			$rightNode   = $leftNode+1;
		}else{
			$leftNode    = 1;
			$rightNode   = 2;
		}
		//更新相关数据的右值信息
		$this->m->where('cate_right >= ?', $leftNode)->field('cate_right', 2);
		//更新相关数据的右值信息
		$this->m->where('cate_left > ?', $leftNode)->field('cate_left', 2);
		//增加新的节点
		$in = array();
		$in['cate_name']      = $name;
		$in['cate_desc']      = $desc;
		$in['cate_left']      = $leftNode;
		$in['cate_right']     = $rightNode;
		$in['cate_order']     = $order;
		$this->m->add($in);
	}
	
	//根据节点id查询节点信息
	public function getNodeById($id){
		return $this->m->where('cate_id = ?', $id)->fetch();
	}
	
	//根据节点名称查询节点信息
	public function getNodeByName($name){
		return $this->m->where('cate_name = ?', $name)->fetch();
	}
	
	//获取符合条件的节点
	//type : 1,所有子类,不包含自己;2包含自己的所有子类;3不包含自己所有父类4;包含自己所有父类
	public function getNodes($CatagoryID, $type = 1){
		//获取当前节点信息
		$Result        = $this->getNodeById($CatagoryID);
		$Lft           = $Result['cate_left'];
		$Rgt           = $Result['cate_right'];
		switch ($type) {
			case 1 :
	    		$where = "`cate_left` > ? AND `cate_right` < ?";
			break;
	    	case 2 :
	    		$where = "`cate_left` >= ? AND `cate_right` <= ?";
	    	break;
	     	case 3 :
				$where = "`cate_left`< ? AND `cate_right` > ?";
			break;
	    	case 4 :
				$where = "`cate_left` <= ? AND `cate_right` >= ?";
	    	break;
	    	default :
	    	$where = "`cate_left` > ? AND `cate_right` < ?";
	    }
		return $this->m->where($where, array($Lft, $Rgt))->fetchAll();
	}
	
	public function moveNode($SelfCatagoryID, $ParentCatagoryID){
		if($SelfCatagoryID == $ParentCatagoryID){return false;}
		$SelfCatagory  = $this->getNodeById($SelfCatagoryID);
		$NewCatagory   = $this->getNodeById($ParentCatagoryID);
		$SelfLft       = $SelfCatagory['cate_left'];
		$SelfRgt       = $SelfCatagory['cate_right'];
		$Value         = $SelfRgt - $SelfLft;
		//取所有子类分类的id 以备更新左右值
		$CatagoryIDS   = $this->getNodes($SelfCatagoryID,2);
		$IDS           = array();
		foreach($CatagoryIDS as $v){$IDS[] = $v['cate_id'];}
		$InIDS         = implode(",",$IDS);
		
		$ParentLft     = $NewCatagory['cate_left'];
		$ParentRgt     = $NewCatagory['cate_right'];
		
		if($ParentRgt > $SelfRgt) {
			$this->m->where('cate_left > ? and cate_right <= ?', array($SelfLft, $ParentRgt))->field('cate_left', $Value*-1 - 1);
			$this->m->where('cate_right > ? and cate_right < ?', array($SelfRgt, $ParentRgt))->field('cate_right', $Value*-1 - 1);
    		$TmpValue = $ParentRgt - $SelfRgt - 1;
			$this->m->where('`cate_id` IN('.$InIDS.')', null)->field('cate_left', $TmpValue);
			$this->m->where('`cate_id` IN('.$InIDS.')', null)->field('cate_right', $TmpValue);
		}
		else{                    
			$this->m->where('cate_left > ? and cate_left < ?', array($ParentRgt, $SelfLft))->field('cate_left', $Value + 1);
			$this->m->where('cate_right >= ? and cate_right < ?', array($ParentRgt, $SelfLft))->field('cate_right', $Value + 1);
    		$TmpValue     = $ParentRgt - $SelfLft;
			$this->m->where('`cate_id` IN('.$InIDS.')', null)->field('cate_left', $TmpValue);
			$this->m->where('`cate_id` IN('.$InIDS.')', null)->field('cate_right', $TmpValue);
		}	
	}
	
	//获取父节点 直属父类（type=1），所有父类：type=0
	public function getParentNode($nodeId,$type = 1){
		$currentNode = $this->getNodeById($nodeId);
		if(empty($currentNode)){return null;}
		if($type ==1){
			return $this->m
					->where('cate_left < ? and cate_right > ?', array($currentNode['cate_left'],$currentNode['cate_right']))
					->order('cate_left desc')->limit(0,1)->fetch();
		}else{
			return $this->where('cate_left < ? and cate_right > ?', array($currentNode['cate_left'],$currentNode['cate_right']))->fetchAll();
		}
	}
}
