package com.invex.test.authentication.service;

import com.invex.test.authentication.domain.model.Role;
import com.invex.test.authentication.repository.RoleRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AccessControlCatalog {

    private final RoleRepository roleRepository;

    public AccessControlCatalog(RoleRepository roleRepository) {
        this.roleRepository = roleRepository;
    }

    @Transactional
    public Role ensureRole(String code, String description) {
        requireText(code, "Role code is required");
        requireText(description, "Role description is required");
        return roleRepository.findByCode(code)
                .orElseGet(() -> roleRepository.save(new Role(code, description)));
    }

    private static void requireText(String value, String message) {
        if (value == null || value.isBlank()) {
            throw new InvalidAccountDataException(message);
        }
    }
}
