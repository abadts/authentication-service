package com.invex.test.authentication.service;

import com.invex.test.authentication.domain.model.AuthenticationUser;
import com.invex.test.authentication.domain.model.Role;
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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.SimpleTransactionStatus;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserAccountServiceTest {

    private static final String RAW_PASSWORD = "ChangeMe123!";
    private static final String STORED_HASH = "$2a$12$stored-hash";

    @Mock
    private AuthenticationUserRepository userRepository;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private PlatformTransactionManager transactionManager;

    private UserAccountService userAccountService;

    private Role employeeRole;

    @BeforeEach
    void setUp() {
        userAccountService = new UserAccountService(userRepository, roleRepository, passwordEncoder, transactionManager);
        employeeRole = new Role(AuthorizationCodes.EMPLOYEE, "Employee");
    }

    @Test
    void opensAnEmployeeAccountAndStoresTheHash() {
        when(userRepository.findByUsername("karla.chavez")).thenReturn(Optional.empty());
        when(userRepository.findByEmail("karla.chavez@test.invex.local")).thenReturn(Optional.empty());
        when(roleRepository.findByCode(AuthorizationCodes.EMPLOYEE)).thenReturn(Optional.of(employeeRole));
        when(passwordEncoder.encode(RAW_PASSWORD)).thenReturn(STORED_HASH);
        when(userRepository.save(any(AuthenticationUser.class))).thenAnswer(invocation -> invocation.getArgument(0));

        AccountView account = userAccountService.openAccount("karla.chavez", RAW_PASSWORD, "karla.chavez@test.invex.local", "EMPLOYEE");

        ArgumentCaptor<AuthenticationUser> savedAccount = ArgumentCaptor.forClass(AuthenticationUser.class);
        verify(userRepository).save(savedAccount.capture());
        assertThat(savedAccount.getValue().getPasswordHash()).isEqualTo(STORED_HASH);
        assertThat(savedAccount.getValue().getPasswordHash()).doesNotContain(RAW_PASSWORD);
        assertThat(account.username()).isEqualTo("karla.chavez");
        assertThat(account.email()).isEqualTo("karla.chavez@test.invex.local");
        assertThat(account.role()).isEqualTo(AuthorizationCodes.EMPLOYEE);
        assertThat(account.enabled()).isTrue();
    }

    @Test
    void rejectsARepeatedUsername() {
        AuthenticationUser existing = new AuthenticationUser("karla.chavez", STORED_HASH, "karla.chavez@test.invex.local", true, Set.of(employeeRole));
        when(userRepository.findByUsername("karla.chavez")).thenReturn(Optional.of(existing));

        assertThatThrownBy(() -> userAccountService.openAccount("karla.chavez", RAW_PASSWORD, "juan.perez@test.invex.local", "EMPLOYEE"))
                .isInstanceOf(DuplicateAccountException.class)
                .hasMessage("Username is already registered");
        verify(passwordEncoder, never()).encode(any());
        verify(userRepository, never()).save(any());
    }

    @Test
    void rejectsARepeatedEmailIgnoringCase() {
        AuthenticationUser existing = new AuthenticationUser("juan.perez", STORED_HASH, "juan.perez@test.invex.local", true, Set.of(employeeRole));
        when(userRepository.findByUsername("karla.chavez")).thenReturn(Optional.empty());
        when(roleRepository.findByCode(AuthorizationCodes.EMPLOYEE)).thenReturn(Optional.of(employeeRole));
        when(userRepository.findByEmail("juan.perez@test.invex.local")).thenReturn(Optional.of(existing));

        assertThatThrownBy(() -> userAccountService.openAccount("karla.chavez", RAW_PASSWORD, "Juan.Perez@test.invex.local", "EMPLOYEE"))
                .isInstanceOf(DuplicateAccountException.class)
                .hasMessage("Email is already registered");
        verify(passwordEncoder, never()).encode(any());
        verify(userRepository, never()).save(any());
    }

    @Test
    void refusesToOpenAnAdministratorAccount() {
        assertThatThrownBy(() -> userAccountService.openAccount("karla.chavez", RAW_PASSWORD, "karla.chavez@test.invex.local", "ADMIN"))
                .isInstanceOf(AccountRoleNotAllowedException.class)
                .hasMessage("Only an EMPLOYEE account can be opened");
        verify(userRepository, never()).save(any());
        verify(passwordEncoder, never()).encode(any());
    }

    @Test
    void leavesAnExistingAccountUntouched() {
        Role administrator = new Role(AuthorizationCodes.ADMINISTRATOR, "Administrator");
        AuthenticationUser existing = new AuthenticationUser("admin", STORED_HASH, "admin@test.invex.local", true, Set.of(administrator));
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(existing));

        AuthenticationUser account = userAccountService.registerIfAbsent(
                "admin",
                "ChangeMe123!",
                "juan.perez@test.invex.local",
                false,
                Set.of(administrator)
        );

        assertThat(account.getPasswordHash()).isEqualTo(STORED_HASH);
        assertThat(account.getEmail()).isEqualTo("admin@test.invex.local");
        assertThat(account.isEnabled()).isTrue();
        verify(passwordEncoder, never()).encode(any());
        verify(userRepository, never()).save(any());
    }

    @Test
    void deletesAnExistingAccount() {
        AuthenticationUser existing = new AuthenticationUser(
                "karla.chavez",
                STORED_HASH,
                "karla.chavez@test.invex.local",
                true,
                Set.of(employeeRole)
        );
        when(userRepository.findByUsername("karla.chavez")).thenReturn(Optional.of(existing));

        userAccountService.deleteAccount("karla.chavez");

        verify(userRepository).delete(existing);
        verify(roleRepository, never()).delete(any(Role.class));
    }

    @Test
    void rejectsDeletionOfAMissingAccount() {
        when(userRepository.findByUsername("juan.perez")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> userAccountService.deleteAccount("juan.perez"))
                .isInstanceOf(AccountNotFoundException.class)
                .hasMessage("Account was not found");
        verify(userRepository, never()).delete(any());
    }

    @Test
    void reportsExistingUsernamesAndEmailsIncludingDisabledAccounts() {
        when(userRepository.findExistingUsernames(anyCollection())).thenReturn(List.of("karla.chavez", "disabled.user"));
        when(userRepository.findExistingEmails(anyCollection())).thenReturn(List.of(
                "juan.perez@test.invex.local",
                "disabled.user@test.invex.local"
        ));

        AccountLookupReport report = userAccountService.validateAccounts(List.of(
                new AccountLookup("karla.chavez", "free.mail@test.invex.local"),
                new AccountLookup("free.user", "Juan.Perez@test.invex.local"),
                new AccountLookup("disabled.user", "disabled.user@test.invex.local"),
                new AccountLookup("new.user", "new.user@test.invex.local")
        ));

        assertThat(report.results()).containsExactly(
                new AccountLookupResult("karla.chavez", "free.mail@test.invex.local", true, false),
                new AccountLookupResult("free.user", "Juan.Perez@test.invex.local", false, true),
                new AccountLookupResult("disabled.user", "disabled.user@test.invex.local", true, true),
                new AccountLookupResult("new.user", "new.user@test.invex.local", false, false)
        );
        verify(userRepository, times(1)).findExistingUsernames(Set.of(
                "karla.chavez",
                "free.user",
                "disabled.user",
                "new.user"
        ));
        verify(userRepository, times(1)).findExistingEmails(Set.of(
                "free.mail@test.invex.local",
                "juan.perez@test.invex.local",
                "disabled.user@test.invex.local",
                "new.user@test.invex.local"
        ));
        verify(userRepository, never()).save(any());
    }

    @Test
    void createsEveryAccount() {
        allowAccountCreation();

        AccountBatchReport report = userAccountService.createAccounts(List.of(
                draft("karla.chavez", "karla.chavez@test.invex.local"),
                draft("juan.perez", "juan.perez@test.invex.local")
        ));

        assertThat(report.results()).containsExactly(
                created("karla.chavez", "karla.chavez@test.invex.local"),
                created("juan.perez", "juan.perez@test.invex.local")
        );
        ArgumentCaptor<AuthenticationUser> savedAccounts = ArgumentCaptor.forClass(AuthenticationUser.class);
        verify(userRepository, times(2)).save(savedAccounts.capture());
        assertThat(savedAccounts.getAllValues()).allSatisfy(account -> {
            assertThat(account.getPasswordHash()).isEqualTo(STORED_HASH);
            assertThat(account.getPasswordHash()).doesNotContain(RAW_PASSWORD);
            assertThat(account.isEnabled()).isTrue();
            assertThat(account.getRoles()).extracting(Role::getCode).containsExactly(AuthorizationCodes.EMPLOYEE);
        });
    }

    @Test
    void createsTheOtherAccountWhenOneUsernameAlreadyExists() {
        allowAccountCreation();
        AuthenticationUser existing = new AuthenticationUser(
                "karla.chavez",
                STORED_HASH,
                "karla.chavez@test.invex.local",
                true,
                Set.of(employeeRole)
        );
        when(userRepository.findByUsername("karla.chavez")).thenReturn(Optional.of(existing));

        AccountBatchReport report = userAccountService.createAccounts(List.of(
                draft("karla.chavez", "karla.chavez@test.invex.local"),
                draft("juan.perez", "juan.perez@test.invex.local")
        ));

        assertThat(report.results()).containsExactly(
                conflict("karla.chavez", "karla.chavez@test.invex.local", "USERNAME_ALREADY_EXISTS"),
                created("juan.perez", "juan.perez@test.invex.local")
        );
        verify(userRepository, times(1)).save(any(AuthenticationUser.class));
    }

    @Test
    void createsTheOtherAccountWhenOneEmailAlreadyExists() {
        allowAccountCreation();
        when(userRepository.findExistingEmails(Set.of("karla.chavez@test.invex.local")))
                .thenReturn(List.of("karla.chavez@test.invex.local"));

        AccountBatchReport report = userAccountService.createAccounts(List.of(
                draft("karla.chavez", "karla.chavez@test.invex.local"),
                draft("juan.perez", "juan.perez@test.invex.local")
        ));

        assertThat(report.results()).containsExactly(
                conflict("karla.chavez", "karla.chavez@test.invex.local", "EMAIL_ALREADY_EXISTS"),
                created("juan.perez", "juan.perez@test.invex.local")
        );
        verify(userRepository, times(1)).save(any(AuthenticationUser.class));
    }

    @Test
    void treatsADisabledAccountAsExisting() {
        allowAccountCreation();
        AuthenticationUser disabled = new AuthenticationUser(
                "karla.chavez",
                STORED_HASH,
                "karla.chavez@test.invex.local",
                false,
                Set.of(employeeRole)
        );
        when(userRepository.findByUsername("karla.chavez")).thenReturn(Optional.of(disabled));

        AccountBatchReport report = userAccountService.createAccounts(List.of(
                draft("karla.chavez", "another.mail@test.invex.local"),
                draft("juan.perez", "juan.perez@test.invex.local")
        ));

        assertThat(disabled.isEnabled()).isFalse();
        assertThat(report.results()).containsExactly(
                conflict("karla.chavez", "another.mail@test.invex.local", "USERNAME_ALREADY_EXISTS"),
                created("juan.perez", "juan.perez@test.invex.local")
        );
        verify(userRepository, never()).save(argThat(account -> "karla.chavez".equals(account.getUsername())));
    }

    @Test
    void rejectsADuplicateUsernameInsideTheBatch() {
        allowAccountCreation();

        AccountBatchReport report = userAccountService.createAccounts(List.of(
                draft("karla.chavez", "karla.chavez@test.invex.local"),
                draft("karla.chavez", "juan.perez@test.invex.local")
        ));

        assertThat(report.results()).containsExactly(
                created("karla.chavez", "karla.chavez@test.invex.local"),
                conflict("karla.chavez", "juan.perez@test.invex.local", "DUPLICATE_USERNAME_IN_BATCH")
        );
        verify(userRepository, times(1)).save(any(AuthenticationUser.class));
    }

    @Test
    void rejectsADuplicateEmailInsideTheBatchIgnoringCase() {
        allowAccountCreation();

        AccountBatchReport report = userAccountService.createAccounts(List.of(
                draft("karla.chavez", "karla.chavez@test.invex.local"),
                draft("juan.perez", "Karla.Chavez@test.invex.local")
        ));

        assertThat(report.results()).containsExactly(
                created("karla.chavez", "karla.chavez@test.invex.local"),
                conflict("juan.perez", "Karla.Chavez@test.invex.local", "DUPLICATE_EMAIL_IN_BATCH")
        );
        verify(userRepository, times(1)).save(any(AuthenticationUser.class));
    }

    @Test
    void continuesAfterAPersistenceFailure() {
        allowAccountReads();
        when(userRepository.save(any(AuthenticationUser.class))).thenAnswer(invocation -> {
            AuthenticationUser account = invocation.getArgument(0);
            if ("karla.chavez".equals(account.getUsername())) {
                throw new DataIntegrityViolationException("Duplicate entry for key uk_user_username");
            }
            return account;
        });

        AccountBatchReport report = userAccountService.createAccounts(List.of(
                draft("karla.chavez", "karla.chavez@test.invex.local"),
                draft("juan.perez", "juan.perez@test.invex.local")
        ));

        assertThat(report.results()).containsExactly(
                conflict("karla.chavez", "karla.chavez@test.invex.local", "USERNAME_ALREADY_EXISTS"),
                created("juan.perez", "juan.perez@test.invex.local")
        );
    }

    @Test
    void returnsOneResultPerAccountInTheRequestOrder() {
        allowAccountCreation();
        when(userRepository.findExistingEmails(Set.of("juan.perez@test.invex.local")))
                .thenReturn(List.of("juan.perez@test.invex.local"));

        AccountBatchReport report = userAccountService.createAccounts(List.of(
                new AccountDraft("ab", RAW_PASSWORD, "ab@test.invex.local"),
                draft("karla.chavez", "karla.chavez@test.invex.local"),
                draft("juan.perez", "juan.perez@test.invex.local")
        ));

        assertThat(report.results()).containsExactly(
                new AccountBatchResult("ab", "ab@test.invex.local", "INVALID", "USERNAME_LENGTH_INVALID"),
                created("karla.chavez", "karla.chavez@test.invex.local"),
                conflict("juan.perez", "juan.perez@test.invex.local", "EMAIL_ALREADY_EXISTS")
        );
    }

    private void allowAccountCreation() {
        allowAccountReads();
        when(userRepository.save(any(AuthenticationUser.class))).thenAnswer(invocation -> invocation.getArgument(0));
    }

    private void allowAccountReads() {
        when(transactionManager.getTransaction(any())).thenAnswer(invocation -> new SimpleTransactionStatus());
        when(userRepository.findByUsername(any())).thenReturn(Optional.empty());
        when(userRepository.findByEmail(any())).thenReturn(Optional.empty());
        when(userRepository.findExistingEmails(any())).thenReturn(List.of());
        when(roleRepository.findByCode(AuthorizationCodes.EMPLOYEE)).thenReturn(Optional.of(employeeRole));
        when(passwordEncoder.encode(RAW_PASSWORD)).thenReturn(STORED_HASH);
    }

    private static AccountDraft draft(String username, String email) {
        return new AccountDraft(username, RAW_PASSWORD, email);
    }

    private static AccountBatchResult created(String username, String email) {
        return new AccountBatchResult(username, email, "CREATED", null);
    }

    private static AccountBatchResult conflict(String username, String email, String reason) {
        return new AccountBatchResult(username, email, "CONFLICT", reason);
    }
}
