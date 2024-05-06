<?php
# api/src/State/UserPasswordHasher.php

namespace App\State;

use ApiPlatform\Metadata\Operation;
use ApiPlatform\State\ProcessorInterface;
use App\Entity\User;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

final class UserPasswordHasher implements ProcessorInterface
{
    public function __construct(private readonly ProcessorInterface $processor, private readonly UserPasswordHasherInterface $passwordHasher)
    {
    }

    /**
     * Processes the state.
     *
     * @param array<string, mixed> $uriVariables
     * @param array<string, mixed> $context
     *
     * @return T
     */
    public function process(mixed $data, Operation $operation, array $uriVariables = [], array $context = [])
    {
        if(!$data instanceof User) {
            return $this->processor->process($data, $operation, $uriVariables, $context);
        }

        $this->checkForRawPWD($data);

        return $this->processor->process($data, $operation, $uriVariables, $context);
    }

    private function checkForRawPWD(User &$data) {
        if (!$data->getRawPassword() || empty($data->getRawPassword())) {
            return;
        }

        $hashedPassword = $this->passwordHasher->hashPassword(
            $data,
            $data->getRawPassword()
        );
        $data->setPassword($hashedPassword);
        $data->eraseCredentials();
    }
}