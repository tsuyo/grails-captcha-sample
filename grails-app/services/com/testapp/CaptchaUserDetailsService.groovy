package com.testapp

import org.codehaus.groovy.grails.plugins.springsecurity.GrailsUser
import org.codehaus.groovy.grails.plugins.springsecurity.GrailsUserDetailsService
import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils
import org.codehaus.groovy.grails.web.servlet.mvc.GrailsHttpSession
import org.codehaus.groovy.grails.web.servlet.mvc.GrailsWebRequest
import org.springframework.dao.DataAccessException
import org.springframework.security.core.authority.GrantedAuthorityImpl
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.web.context.request.RequestContextHolder

import com.megatome.grails.RecaptchaService

class CaptchaUserDetailsService implements GrailsUserDetailsService {
	static final List NO_ROLES = [new GrantedAuthorityImpl(SpringSecurityUtils.NO_ROLE)]
	
	def recaptchaService

	@Override
	public UserDetails loadUserByUsername(String username, boolean loadRoles)
	throws UsernameNotFoundException, DataAccessException {
		return loadUserByUsername(username)
	}
	
	@Override
	public UserDetails loadUserByUsername(String username)
	throws UsernameNotFoundException, DataAccessException {
		User.withTransaction { status ->
			User user = User.findByUsername(username)
			if (!user) throw new UsernameNotFoundException(
				'User not found', username)
			println "[TM] authorized by password"
			
			def request = RequestContextHolder.currentRequestAttributes().currentRequest
			def session = RequestContextHolder.currentRequestAttributes().session
			
			def paramMap = request.parameterMap
			def params = [
				recaptcha_challenge_field: paramMap.recaptcha_challenge_field[0],
				recaptcha_response_field: paramMap.recaptcha_response_field[0]
				]
			
			if (!recaptchaService.verifyAnswer(session, request.getRemoteAddr(), params)) {
				throw new UsernameNotFoundException(
					'Incorrect Captcha', username)
		    }
			
			println "[TM] authorized by captcha"

			def authorities = user.authorities.collect {
				new GrantedAuthorityImpl(it.authority)
			}

			return new GrailsUser(user.username, user.password, user.enabled,
				!user.accountExpired, !user.passwordExpired,
				!user.accountLocked, authorities ?: NO_ROLES, user.id)
		}
	}
}
