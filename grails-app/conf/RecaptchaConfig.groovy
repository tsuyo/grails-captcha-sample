recaptcha {
    // These keys are generated by the ReCaptcha service
	publicKey = "6LfajdQSAAAAAEm0Ho-J0193tQQUQ1hAIek8pBZ-"
	privateKey = "6LfajdQSAAAAAA-lGneUFMlFcHSYxhaEfXT6-Rs5"

	// Include the noscript tags in the generated captcha
	includeNoScript = true
}

mailhide {
    // Generated by the Mailhide service
    publicKey = ""
    privateKey = ""
}

environments {
  development {
    recaptcha {
      // Set to false to disable the display of captcha
      enabled = true

      // Communicate using HTTPS
      useSecureAPI = false
    }
  }
  production {
    recaptcha {
      // Set to false to disable the display of captcha
      enabled = true

      // Communicate using HTTPS
      useSecureAPI = true
    }
  }
}