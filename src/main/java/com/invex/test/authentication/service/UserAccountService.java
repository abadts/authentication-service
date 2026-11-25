package com.invex.test.authentication.service;

import com.invex.test.authentication.domain.model.Role;
import com.invex.test.authentication.domain.model.AuthenticationUser;
import com.invex.test.authentication.dto.AccountBatchReport;
import com.invex.test.authentication.dto.AccountBatchResult;
import com.invex.test.authentication.dto.AccountDraft;
import com.invex.test.authentication.dto.AccountLookup;
import com.invex.test.authentication.dto.AccountLookupReport;
import com.invex.test.authentication.dto.AccountLookupResult;
import com.invex.test.authentication.dto.AccountView;
import com.invex.test.authentication.repository.AuthenticationUserRepository;
import com.invex.test.authentication.repository.RoleRepository;
import com.invex.test.authentication.security.AuthorizationCodes;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

@Service
public class UserAccountService {

    static final int MINIMUM_USERNAME_LENGTH = 3;
    static final int MAXIMUM_USERNAME_LENGTH = 80;
    static final int MINIMUM_PASSWORD_LENGTH = 5;
    private static final Pattern USERNAME_PATTERN = Pattern.compile("[A-Za-z0-9._-]+");
    private static final String CREATED = "CREATED";
    private static final String CONFLICT = "CONFLICT";
    private static final String INVALID = "INVALID";
    private static final String USERNAME_ALREADY_EXISTS = "USERNAME_ALREADY_EXISTS";
    private static final String EMAIL_ALREADY_EXISTS = "EMAIL_ALREADY_EXISTS";
    private static final String USERNAME_AND_EMAIL_ALREADY_EXIST = "USERNAME_AND_EMAIL_ALREADY_EXIST";
    private static final String DUPLICATE_USERNAME_IN_BATCH = "DUPLICATE_USERNAME_IN_BATCH";
    private static final String DUPLICATE_EMAIL_IN_BATCH = "DUPLICATE_EMAIL_IN_BATCH";
    private static final String USERNAME_CONSTRAINT = "uk_user_username";
    private static final String EMAIL_CONSTRAINT = "uk_user_email";

    private final AuthenticationUserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final TransactionTemplate accountTransaction;

    public UserAccountService(AuthenticationUserRepository userRepository,
                              RoleRepository roleRepository,
                              PasswordEncoder passwordEncoder,
                              PlatformTransactionManager transactionManager) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.accountTransaction = new TransactionTemplate(transactionManager);
        this.accountTransaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    @Transactional(readOnly = true)
    public AccountLookupReport validateAccounts(List<AccountLookup> accounts) {
        if (accounts == null) {
            throw new InvalidAccountDataException("Accounts are required");
        }
        Set<String> usernames = new LinkedHashSet<>();
        Set<String> emails = new LinkedHashSet<>();
        for (AccountLookup account : accounts) {
            if (account == null) {
                throw new InvalidAccountDataException("Account is required");
            }
            String username = lookupUsername(account.username());
            String email = lookupEmail(account.email());
            if (username != null) {
                usernames.add(username);
            }
            if (email != null) {
                emails.add(email);
            }
        }
        Set<String> existingUsernames = usernames.isEmpty()
                ? Set.of()
                : new HashSet<>(userRepository.findExistingUsernames(usernames));
        Set<String> existingEmails = emails.isEmpty()
                ? Set.of()
                : new HashSet<>(userRepository.findExistingEmails(emails));
        List<AccountLookupResult> results = new ArrayList<>();
        for (AccountLookup account : accounts) {
            String username = lookupUsername(account.username());
            String email = lookupEmail(account.email());
            results.add(new AccountLookupResult(
                    account.username(),
                    account.email(),
                    username != null && existingUsernames.contains(username),
                    email != null && existingEmails.contains(email)
            ));
        }
        return new AccountLookupReport(results);
    }

    public AccountBatchReport createAccounts(List<AccountDraft> accounts) {
        if (accounts == null) {
            throw new InvalidAccountDataException("Accounts are required");
        }
        Set<String> reservedUsernames = new LinkedHashSet<>();
        Set<String> reservedEmails = new LinkedHashSet<>();
        List<AccountBatchResult> results = new ArrayList<>();
        for (AccountDraft account : accounts) {
            results.add(createAccount(account, reservedUsernames, reservedEmails));
        }
        return new AccountBatchReport(results);
    }

    @Transactional(readOnly = true)
    public Optional<String> emailOf(String username) {
        if (username == null || username.isBlank()) {
            return Optional.empty();
        }
        return userRepository.findByUsername(username.trim()).map(AuthenticationUser::getEmail);
    }

    @Transactional
    public AuthenticationUser registerIfAbsent(String username, String rawPassword, String email, boolean enabled, Set<Role> roles) {
        String normalizedUsername = requireUsername(username);
        AuthenticationUser account = userRepository.findByUsername(normalizedUsername)
                .orElseGet(() -> create(normalizedUsername, rawPassword, email, enabled, roles));
        account.assignCreatedAtIfMissing();
        return account;
    }

    @Transactional
    public AccountView openAccount(String username, String rawPassword, String email, String roleCode) {
        String normalizedUsername = requireUsername(username);
        requirePassword(rawPassword);
        String normalizedEmail = requireEmail(email);
        String normalizedRole = requireRoleCode(roleCode);
        if (!AuthorizationCodes.EMPLOYEE.equals(normalizedRole)) {
            throw new AccountRoleNotAllowedException("Only an EMPLOYEE account can be opened");
        }
        if (userRepository.findByUsername(normalizedUsername).isPresent()) {
            throw new DuplicateAccountException("Username is already registered");
        }
        Role employee = roleRepository.findByCode(AuthorizationCodes.EMPLOYEE)
                .orElseThrow(() -> new InvalidAccountDataException("Role was not found"));
        AuthenticationUser created = create(normalizedUsername, rawPassword, normalizedEmail, true, Set.of(employee));
        return new AccountView(created.getUsername(), created.getEmail(), employee.getCode(), created.isEnabled());
    }

    @Transactional
    public void deleteAccount(String username) {
        String normalizedUsername = requireUsername(username);
        AuthenticationUser account = userRepository.findByUsername(normalizedUsername)
                .orElseThrow(() -> new AccountNotFoundException("Account was not found"));
        userRepository.delete(account);
    }

    private AccountBatchResult createAccount(AccountDraft account,
                                             Set<String> reservedUsernames,
                                             Set<String> reservedEmails) {
        if (account == null) {
            return new AccountBatchResult(null, null, INVALID, "ACCOUNT_REQUIRED");
        }
        String username;
        String email;
        try {
            username = requireUsername(account.username());
            requirePassword(account.password());
            email = requireEmail(account.email());
        } catch (InvalidAccountDataException exception) {
            return new AccountBatchResult(account.username(), account.email(), INVALID, invalidReason(exception));
        }
        if (reservedUsernames.contains(username)) {
            return new AccountBatchResult(account.username(), account.email(), CONFLICT, DUPLICATE_USERNAME_IN_BATCH);
        }
        if (reservedEmails.contains(email)) {
            return new AccountBatchResult(account.username(), account.email(), CONFLICT, DUPLICATE_EMAIL_IN_BATCH);
        }
        boolean usernameExists = userRepository.findByUsername(username).isPresent();
        boolean emailExists = emailExists(email);
        if (usernameExists || emailExists) {
            reserveExisting(username, email, usernameExists, emailExists, reservedUsernames, reservedEmails);
            return new AccountBatchResult(
                    account.username(),
                    account.email(),
                    CONFLICT,
                    conflictReason(usernameExists, emailExists)
            );
        }
        try {
            accountTransaction.executeWithoutResult(status -> create(
                    username,
                    account.password(),
                    email,
                    true,
                    Set.of(employeeRole())
            ));
        } catch (InvalidAccountDataException exception) {
            return new AccountBatchResult(account.username(), account.email(), INVALID, invalidReason(exception));
        } catch (RuntimeException exception) {
            AccountBatchResult conflict = persistenceConflict(account, username, email, exception);
            if (conflict == null) {
                throw exception;
            }
            reservedUsernames.add(username);
            reservedEmails.add(email);
            return conflict;
        }
        reservedUsernames.add(username);
        reservedEmails.add(email);
        return new AccountBatchResult(account.username(), account.email(), CREATED, null);
    }

    private Role employeeRole() {
        return roleRepository.findByCode(AuthorizationCodes.EMPLOYEE)
                .orElseThrow(() -> new InvalidAccountDataException("Role was not found"));
    }

    private boolean emailExists(String email) {
        return !userRepository.findExistingEmails(Set.of(email)).isEmpty();
    }

    private static void reserveExisting(String username,
                                        String email,
                                        boolean usernameExists,
                                        boolean emailExists,
                                        Set<String> reservedUsernames,
                                        Set<String> reservedEmails) {
        if (usernameExists) {
            reservedUsernames.add(username);
        }
        if (emailExists) {
            reservedEmails.add(email);
        }
    }

    private AccountBatchResult persistenceConflict(AccountDraft account,
                                                   String username,
                                                   String email,
                                                   RuntimeException exception) {
        if (exception instanceof DuplicateAccountException) {
            return new AccountBatchResult(account.username(), account.email(), CONFLICT, EMAIL_ALREADY_EXISTS);
        }
        if (!(exception instanceof DataIntegrityViolationException integrityViolation)) {
            return null;
        }
        String details = "";
        Throwable cause = integrityViolation.getMostSpecificCause();
        if (cause.getMessage() != null) {
            details = cause.getMessage().toLowerCase(Locale.ROOT);
        }
        boolean usernameTaken = details.contains(USERNAME_CONSTRAINT);
        boolean emailTaken = details.contains(EMAIL_CONSTRAINT);
        if (!usernameTaken && !emailTaken) {
            usernameTaken = userRepository.findByUsername(username).isPresent();
            emailTaken = emailExists(email);
        }
        if (!usernameTaken && !emailTaken) {
            return new AccountBatchResult(account.username(), account.email(), CONFLICT, USERNAME_ALREADY_EXISTS);
        }
        return new AccountBatchResult(
                account.username(),
                account.email(),
                CONFLICT,
                conflictReason(usernameTaken, emailTaken)
        );
    }

    private static String conflictReason(boolean usernameExists, boolean emailExists) {
        if (usernameExists && emailExists) {
            return USERNAME_AND_EMAIL_ALREADY_EXIST;
        }
        if (usernameExists) {
            return USERNAME_ALREADY_EXISTS;
        }
        return EMAIL_ALREADY_EXISTS;
    }

    private static String invalidReason(InvalidAccountDataException exception) {
        String message = exception.getMessage();
        if ("Username is required".equals(message)) {
            return "USERNAME_REQUIRED";
        }
        if ("Username length is invalid".equals(message)) {
            return "USERNAME_LENGTH_INVALID";
        }
        if ("Username contains unsupported characters".equals(message)) {
            return "USERNAME_INVALID";
        }
        if ("Password does not meet the minimum length".equals(message)) {
            return "PASSWORD_INVALID";
        }
        if ("Email is required".equals(message)) {
            return "EMAIL_REQUIRED";
        }
        if ("Email is invalid".equals(message)) {
            return "EMAIL_INVALID";
        }
        return "ACCOUNT_INVALID";
    }

    private AuthenticationUser create(String username, String rawPassword, String email, boolean enabled, Set<Role> roles) {
        requirePassword(rawPassword);
        String normalizedEmail = requireEmail(email);
        if (roles == null || roles.isEmpty()) {
            throw new InvalidAccountDataException("A user requires at least one role");
        }
        if (userRepository.findByEmail(normalizedEmail).isPresent()) {
            throw new DuplicateAccountException("Email is already registered");
        }
        AuthenticationUser user = new AuthenticationUser(
                username,
                passwordEncoder.encode(rawPassword),
                normalizedEmail,
                enabled,
                roles
        );
        return userRepository.save(user);
    }

    private static String lookupUsername(String username) {
        if (username == null || username.isBlank()) {
            return null;
        }
        return username.trim();
    }

    private static String lookupEmail(String email) {
        if (email == null || email.isBlank()) {
            return null;
        }
        return email.trim().toLowerCase(Locale.ROOT);
    }

    private static String requireUsername(String username) {
        if (username == null || username.isBlank()) {
            throw new InvalidAccountDataException("Username is required");
        }
        String normalized = username.trim();
        if (normalized.length() < MINIMUM_USERNAME_LENGTH || normalized.length() > MAXIMUM_USERNAME_LENGTH) {
            throw new InvalidAccountDataException("Username length is invalid");
        }
        if (!USERNAME_PATTERN.matcher(normalized).matches()) {
            throw new InvalidAccountDataException("Username contains unsupported characters");
        }
        return normalized;
    }

    private static void requirePassword(String rawPassword) {
        if (rawPassword == null || rawPassword.length() < MINIMUM_PASSWORD_LENGTH) {
            throw new InvalidAccountDataException("Password does not meet the minimum length");
        }
    }

    private static String requireEmail(String email) {
        if (email == null || email.isBlank()) {
            throw new InvalidAccountDataException("Email is required");
        }
        String normalized = email.trim().toLowerCase(Locale.ROOT);
        int atSign = normalized.indexOf('@');
        boolean singleAtSign = atSign > 0 && atSign == normalized.lastIndexOf('@');
        boolean domainHasDot = singleAtSign && normalized.substring(atSign + 1).contains(".");
        if (!domainHasDot) {
            throw new InvalidAccountDataException("Email is invalid");
        }
        return normalized;
    }

    private static String requireRoleCode(String roleCode) {
        if (roleCode == null || roleCode.isBlank()) {
            throw new InvalidAccountDataException("Role is required");
        }
        return roleCode.trim();
    }
}
