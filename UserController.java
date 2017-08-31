package com.ehootu.web.controller;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.ehootu.core.feature.orm.mybatis.Page;
import com.ehootu.core.util.ApplicationUtils;
import com.ehootu.core.util.ShiroUtils;
import com.ehootu.core.util.StringUtils;
import com.ehootu.web.model.BaseInfo;
import com.ehootu.web.model.house.ApprovalHP;
import com.ehootu.web.model.house.House;
import com.ehootu.web.model.house.HouseExample;
import com.ehootu.web.model.house.OutPutHouse;
import com.ehootu.web.model.user.PersonInfo;
import com.ehootu.web.model.user.PersonInfoExample;
import com.ehootu.web.model.user.PersonInfoExample.Criteria;
import com.ehootu.web.model.user.PoliceInfo;
import com.ehootu.web.service.user.UserService;
import com.google.code.kaptcha.Constants;

/**
 * 
 * @Title: UserController.java
 * @Package com.ehootu.web.controller
 * @Description: TODO(用户控制器)
 * @author zhangyong
 * @date 2017年6月14日 下午2:42:41
 * @version V1.0
 */
@Controller
@RequestMapping(value = "/user")
public class UserController extends BaseController {

	@Autowired
	private UserService userService;

	private final static Logger log = LoggerFactory.getLogger(UserController.class);

	/**
	 * PC端用户登录
	 */
	@RequestMapping(value = "/login", method = RequestMethod.POST)
	public void login(String data, HttpServletRequest request) {
		try {
			PersonInfo user = getJsonAjax(data, PersonInfo.class);

			System.out.println(user);
			Subject subject = ShiroUtils.getSubject();
			// 验证码
			String kaptcha = ShiroUtils.getKaptcha(Constants.KAPTCHA_SESSION_KEY);
			if (!user.getCode().equalsIgnoreCase(kaptcha)) {
				resultError("2", "验证码不正确");
				return;
			}
			// 身份验证 sha256 加密
			user.setUserPassword(ApplicationUtils.sha256Hex(user.getUserPassword()));
			subject.login(new UsernamePasswordToken(user.getUserName(), user.getUserPassword()));

			// 验证成功在Session中保存用户信息
			PersonInfo authUserInfo = userService.selectByUsername(user.getUserName());

			request.getSession().setAttribute("userInfo", authUserInfo);
			// 插入登录 Log
			// 返回成功
			resultSuccess(authUserInfo);

		} catch (AuthenticationException e) {
			// 身份验证失败
			e.printStackTrace();
			resultError("11", "用户名或密码错误！");
		}

	}

	/**
	 * 用户列表查询
	 * 
	 * @param user
	 * @return
	 */
	@RequestMapping("/tablelist")
	@ResponseBody
	public void tableJson(PersonInfo user) {
		PersonInfoExample ue = new PersonInfoExample();
		if (StringUtils.isNoneBlank(user.getUserName())) {
			Criteria criteria = ue.createCriteria();
			criteria.andUserNameLike("%" + user.getUserName() + "%");
		}
		Page<PersonInfo> page = new Page<>((BaseInfo) user);
		page = userService.selectByExampleAndPage(page, ue);
		resultTableJson(page);
	}

	/**
	 * 用户登出
	 *
	 * @return
	 */
	@RequestMapping(value = "/logout", method = RequestMethod.GET)
	public String logout() {

		ShiroUtils.logout();
		// 注销 Log
		return "redirect:/login.html";
	}

	/**
	 * 注册添加用户 | 修改用户信息
	 * 
	 * @param user
	 */

	@RequestMapping("/app/adduser")
	public void appAddUser(PersonInfo user) {
		log.info("PersonInfo--" + user);
		try {
			if (null == user.getId()) {
				// 判断是否有重复
				List<PersonInfo> personInfos = userService.findUser(user);
				if (null == personInfos || personInfos.size() == 0) {
					user.setUserPassword(ApplicationUtils.sha256Hex(user.getUserPassword()));
					userService.insert(user);
					resultSuccess();
				} else {
					resultError("11", "该用户已存在！");
				}
				// 修改用户
			} else {
				userService.update(user);
				resultSuccess();
			}
		} catch (Exception e) {
			e.printStackTrace();
			resultError("1", "数据库操作异常");
		}

	}

	/**
	 * 根据id查询用户
	 * 
	 * @param user
	 */
	@RequestMapping("/app/queryuser")
	public void queryUser(ApprovalHP approvalHP) {
		log.info("approvalHP---" + approvalHP);
		log.info("人员id---" + approvalHP.getPersonInfoId());
		// 返回 Json
		JSONObject resultJson = new JSONObject();

		try {
			if (null != approvalHP.getPersonInfoId()) {
				PersonInfo personInfo = userService.selectById(approvalHP.getPersonInfoId());
				log.info("personInfo--" + personInfo);
				Map<String, Object> jsonMap = new HashMap<String, Object>();
				jsonMap.put("personInfo", personInfo);
				// 返回json 填充 ，null值也要返回
				resultSuccess2(jsonMap);
			} else {
				resultError("2", "人员id为空");
			}
		} catch (Exception e) {
			e.printStackTrace();
			resultError("1", "数据库操作异常");
		}
	}

	/**
	 * 微信公众号端用户登录
	 */
	@RequestMapping(value = "/app/login" )
	public void appLogin(PersonInfo user) {

		try {
			// PersonInfo user = getJsonAjax(data, PersonInfo.class);
			log.info("PersonInfo--" + user);
			log.info("userName--" + user.getUserName());
			log.info("userPassword--" + user.getUserPassword());
			log.info("code--" + user.getCode());
			
			// 根据登陆电话查询
			PersonInfo personInfo = userService.findPerson(user);
			if (null != personInfo) {
				log.info("PersonInfo--" + user);
				//获取后台验证码
				String kaptcha = ShiroUtils.getKaptcha(Constants.KAPTCHA_SESSION_KEY);
				//对比接收到的验证码和session中存的验证码
				if (!user.getCode().equalsIgnoreCase(kaptcha)) {
					resultError("2", "验证码不正确");
					return;
				}
				// 身份验证 sha256 加密
				user.setUserPassword(ApplicationUtils.sha256Hex(user.getUserPassword()));
				PersonInfo result = userService.login(user);
				if (result != null) {
					result.setLoginSign(result.getId());
					resultSuccess(result);
				} else {
					resultError("11", "用户名或密码错误！");
				}
			} else {
				resultError("11", "您还没有注册哦,请注册！");
			}

		} catch (AuthenticationException e) {
			// 身份验证失败
			e.printStackTrace();
			resultError("11", "用户名或密码错误！");
		}
	}
	
	/**
	 * 微信公众号端用户登录
	 */
	@RequestMapping(value = "/app/loginSign" )
	public void appNoLogin(PersonInfo user) {
		if(user.getLoginSign()!=null){
			PersonInfo	result = userService.selectById(user.getLoginSign());
			if(result!=null){
				resultSuccess(result);
				return;
			}
		}
		resultError("11", "用户名信息已过期！");
	}

	/**
	 * 警务通端用户登录
	 */
	@RequestMapping(value = "/app/policelogin")
	public void policeLogin(PoliceInfo user) {
		String passWord = user.getPolicePassword();
		log.info("policeLogin========>"+user);
		try {
			Session s =  ShiroUtils.getSession();
			log.info("s========>"+s);
			//获取后台验证码
			String kaptcha = ShiroUtils.getKaptcha(Constants.KAPTCHA_SESSION_KEY);
			log.info("kaptcha========>"+kaptcha);
			//对比接收到的验证码和session中存的验证码
			if (!user.getCode().equalsIgnoreCase(kaptcha)) {
				resultError("2", "验证码不正确");
				return;
			}
			//将接收到的密码加密
			user.setPolicePassword(ApplicationUtils.sha256Hex(user.getPolicePassword()));
			//验证码正确将去数据库查询是否存在该用户
			PoliceInfo result = userService.policeLogin(user);
			//result！=null 证明数据库有该用户则返回，否则返回else
			if (result != null) {
				//返回不加密的秘码给前端
				result.setPolicePassword(passWord);
				resultSuccess(result);
			} else {
				resultError("11", "用户名或密码错误！");
			}
		} catch (Exception e) {
			e.printStackTrace();
			resultError("11", "数据库操作异常");
		}
	}

	/**
	 * APP端用户修改密码
	 */
	@RequestMapping(value = "/app/updatepwd")
	public void appUpdatePassWord(PersonInfo user) {
		PersonInfo personInfo = userService.selectById(user.getId());
		personInfo.setUserPassword(ApplicationUtils.sha256Hex(user.getUserPassword()));
		PersonInfoExample example = new PersonInfoExample();
		example.createCriteria().andUserNameEqualTo(personInfo.getUserName());
		// example.createCriteria().andPhoneNumberEqualTo(user.getPhoneNumber());
		PersonInfo result = userService.selectByExample(example);
		if (result != null) {
			if (!result.getUserPassword().equals(ApplicationUtils.sha256Hex(user.getOldPassWord()))) {
				resultError("1", "原密码错误，请确认！");
			} else {
				userService.update(personInfo);
				resultSuccess();
			}
		} else {
			resultError("1", "用户名错误！");
		}
	}

}
