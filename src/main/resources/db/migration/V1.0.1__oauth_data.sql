INSERT INTO oauth_client_details (client_id, client_secret, scope, authorized_grant_types, authorities, access_token_validity,web_server_redirect_uri) VALUES ('client1', '{bcrypt}$2a$04$aLgJy3OAbyc.ZR0/Ey2W6e8XfajRQGwiA5c6siuht31M1qN8ZtlJO', 'read', 'refresh_token,authorization_code,implicit', 'ROLE_CLIENT', 300, 'http://localhost:8082/login/oauth2/code/');
INSERT INTO oauth_client_details (client_id, client_secret, scope, authorized_grant_types, authorities, access_token_validity) VALUES ('client2', '{bcrypt}$2a$04$aLgJy3OAbyc.ZR0/Ey2W6e8XfajRQGwiA5c6siuht31M1qN8ZtlJO', 'read', 'password,client_credentials', 'ROLE_CLIENT', 300);


INSERT INTO users (id, username, password, enabled) VALUES (1, 'adam', '{bcrypt}$2a$04$aLgJy3OAbyc.ZR0/Ey2W6e8XfajRQGwiA5c6siuht31M1qN8ZtlJO', 1);

INSERT INTO authorities (username, authority) VALUES ('adam', 'READ_USER');
