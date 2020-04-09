package com.rk.oauth2.authserver.config;

import java.security.KeyPair;
import javax.sql.DataSource;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@EnableAuthorizationServer
@EnableConfigurationProperties(AuthProperties.class)
@Configuration
public class OAuth2AuthServerConfigurer extends AuthorizationServerConfigurerAdapter {

  private AuthenticationManager authenticationManager;
  private DataSource datasource;
  private AuthProperties authProperties;
  private UserDetailsService userDetailsService;


  public OAuth2AuthServerConfigurer(
      AuthenticationConfiguration authenticationConfiguration, DataSource datasource,
      AuthProperties authProperties,
      UserDetailsService userDetailsService) throws Exception {
    this.authenticationManager = authenticationConfiguration.getAuthenticationManager();
    this.datasource = datasource;
    this.authProperties = authProperties;
    this.userDetailsService = userDetailsService;
  }

  @Override
  public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
    security
        .tokenKeyAccess("permitAll()")
        .checkTokenAccess("isAuthenticated()")
        .allowFormAuthenticationForClients();
  }

  @Override
  public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
    endpoints
        .tokenStore(tokenStore())
        .accessTokenConverter(accessTokenConverter())
        .authenticationManager(this.authenticationManager)
        .userDetailsService(userDetailsService);
  }

  @Bean
  public TokenStore tokenStore() {
    return new JwtTokenStore(accessTokenConverter());
  }

  @Bean
  public JwtAccessTokenConverter accessTokenConverter() {

    AuthProperties.JwtProperties jwtProperties = authProperties.getJwt();
    KeyPair keyPair = keyPair(jwtProperties, keyStoreKeyFactory(jwtProperties));

    JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
    converter.setKeyPair(keyPair);
    return converter;
  }

  private KeyPair keyPair(AuthProperties.JwtProperties jwtProperties, KeyStoreKeyFactory keyStoreKeyFactory) {
    return keyStoreKeyFactory.getKeyPair(jwtProperties.getKeyPairAlias(), jwtProperties.getKeyPairPassword().toCharArray());
  }

  private KeyStoreKeyFactory keyStoreKeyFactory(AuthProperties.JwtProperties jwtProperties) {
    return new KeyStoreKeyFactory(jwtProperties.getKeyStore(), jwtProperties.getKeyStorePassword().toCharArray());
  }

  @Override
  public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
    clients.jdbc(datasource);
  }

  @Bean
  public DefaultTokenServices tokenServices(final TokenStore tokenStore,
      final ClientDetailsService clientDetailsService) {
    DefaultTokenServices tokenServices = new DefaultTokenServices();
    tokenServices.setSupportRefreshToken(true);
    tokenServices.setTokenStore(tokenStore);
    tokenServices.setClientDetailsService(clientDetailsService);
    tokenServices.setAuthenticationManager(this.authenticationManager);
    return tokenServices;
  }
}
