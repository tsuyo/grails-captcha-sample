// Place your Spring DSL code here
beans = {
	userDetailsService(com.testapp.CaptchaUserDetailsService) {
		recaptchaService = ref('recaptchaService')
	}
}
