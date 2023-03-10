package com.example.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebMvcConfig implements WebMvcConfigurer  {
	
	private static final String[] CLASSPATH_RESOURCE_LOCATIONS = {
			"classpath:/static/", "classpath:/public/", "classpath:/",
			"classpath:/resources/", "classpath:/META-INF/resources/",
			"classpath:/META-INF/resources/webjars" };
	
	public void addViewController(ViewControllerRegistry registry) {
		// /에 해당하는 url mapping 을 /common/test로 forward 한다.
		registry.addViewController("/").setViewName("forward:/index");
		// 우선순위를 가장 높게 잡는다.
		registry.setOrder(Ordered.HIGHEST_PRECEDENCE);
		
	}

	public void addResourceHandlers(ResourceHandlerRegistry registry) {
		registry.addResourceHandler("/**").addResourceLocations(CLASSPATH_RESOURCE_LOCATIONS);
	}
	
} 
