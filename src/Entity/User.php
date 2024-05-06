<?php

namespace App\Entity;

use ApiPlatform\Metadata\ApiResource;
use App\Repository\UserRepository;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use App\Controller\Auth\UserInfoController;
use ApiPlatform\Metadata\{GetCollection, Get, Post, Patch, Delete, Put};
use App\Controller\Auth\UserInitController;
use App\State\UserPasswordHasher;
use Symfony\Component\Security\Core\Validator\Constraints\UserPassword;
use Symfony\Component\Validator\Constraints as Assert;
use Symfony\Component\Serializer\Annotation\Groups;
use Lexik\Bundle\JWTAuthenticationBundle\Security\User\JWTUserInterface;


#[ORM\Entity(repositoryClass: UserRepository::class)]
#[ORM\Table(name: '`user`')]
#[ORM\UniqueConstraint(name: 'UNIQ_IDENTIFIER_EMAIL', fields: ['email'])]
#[ApiResource(
    operations: [
        new Get(
            uriTemplate: '/auth/me',
            controller: UserInfoController::class,
            read: false,
            write: false,
            name: "me",
            //openapi: @see OpenApiFactory,
        ),
        new Post(
            uriTemplate: 'auth/signin',
            processor: UserPasswordHasher::class,
            //securityPostDenormalize: ''
        ),
        new Patch(
            processor: UserPasswordHasher::class,
        ),
    ]
)]
class User implements UserInterface, PasswordAuthenticatedUserInterface, JWTUserInterface
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(length: 180)]
    private ?string $email = null;

    /**
     * @var list<string> The user roles
     */
    #[ORM\Column]
    private array $roles = [];


    #[ORM\Column(length: 255, nullable: true)]
    private ?string $password = null;

    #Should NEVER be persited
    #[Assert\NotBlank(groups: ['create:user'])]
    #[Groups(['create:user', 'update:user'])]
    #Should NEVER be persited
    private ?string $rawPassword = null;

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getEmail(): ?string
    {
        return $this->email;
    }

    public function setEmail(string $email): static
    {
        $this->email = $email;

        return $this;
    }

    /**
     * A visual identifier that represents this user.
     *
     * @see UserInterface
     */
    public function getUserIdentifier(): string
    {
        return (string) $this->email;
    }

    /**
     * @see UserInterface
     *
     * @return list<string>
     */
    public function getRoles(): array
    {
        $roles = $this->roles;
        // guarantee every user at least has ROLE_USER
        $roles[] = 'ROLE_USER';

        return array_unique($roles);
    }

    /**
     * @param list<string> $roles
     */
    public function setRoles(array $roles): static
    {
        $this->roles = $roles;

        return $this;
    }

    /**
     * @see PasswordAuthenticatedUserInterface
     */
    public function getPassword(): string
    {
        return $this->password;
    }

    public function setPassword(string $password): static
    {
        $this->password = $password;

        return $this;
    }

    public function getRawPassword(): ?string
    {
        return $this->rawPassword;
    }

    public function setRawPassword(string $password): self
    {
        $this->rawPassword = $password;

        return $this;
    }

    /**
     * @see UserInterface
     */
    public function eraseCredentials(): void
    {
        // If you store any temporary, sensitive data on the user, clear it here
        // $this->plainPassword = null;
    }

    /**
     * @see UserInterface
     */
    public static function createFromPayload($identifier, array $payload): JWTUserInterface
    {
        $u = (new User())->setEmail($identifier);
        $u->setRoles($payload['roles'] ?? null);
        $u->setEmail($payload['email'] ?? '');

        return $u;
    }
}
