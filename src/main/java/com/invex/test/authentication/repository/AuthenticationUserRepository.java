package com.invex.test.authentication.repository;

import com.invex.test.authentication.domain.model.AuthenticationUser;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface AuthenticationUserRepository extends JpaRepository<AuthenticationUser, Long> {

    @EntityGraph(attributePaths = "roles")
    Optional<AuthenticationUser> findByUsername(String username);

    @EntityGraph(attributePaths = "roles")
    Optional<AuthenticationUser> findByEmail(String email);

    @Query("select account.username from AuthenticationUser account where account.username in :usernames")
    List<String> findExistingUsernames(@Param("usernames") Collection<String> usernames);

    @Query("select lower(account.email) from AuthenticationUser account where lower(account.email) in :emails")
    List<String> findExistingEmails(@Param("emails") Collection<String> emails);
}
