package com.keycloak.AuthKeycloak.service;

import com.keycloak.AuthKeycloak.dto.UserDTO;
import org.keycloak.representations.idm.UserRepresentation;

import java.util.List;

public interface IKeycloakService {

  List<UserRepresentation> findAllUsers();
  List<UserRepresentation> searchUserByUsername(String username);
  String createUser(UserDTO userDTO);
  void deleteUser(String userId);
  void updateUser(String userId, UserDTO userDTO);

}
