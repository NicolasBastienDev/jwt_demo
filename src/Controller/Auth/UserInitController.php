<?php

namespace App\Controller\Auth;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpKernel\Attribute\AsController;
use App\Repository\UserRepository;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Bundle\SecurityBundle\Security;

use Doctrine\ORM\EntityManagerInterface;

use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;

#[AsController]
class UserInitController extends AbstractController
{
    public function __construct(private Security $security, private UserRepository $userRepository, private RequestStack $request_stack)
    {
    }

    public function __invoke(UserPasswordHasherInterface $hasher, ValidatorInterface $validator, EntityManagerInterface $EMI): Response
    {
        $request = $this->request_stack->getCurrentRequest();
        $params = $request->toArray();

        if (!array_key_exists('username', $params) || !is_string($params['username'])) {
            return new Response(status: Response::HTTP_BAD_REQUEST);
        }

        $user = $this->userRepository->findOneBy(array('email' => $params['username']));

        $user->setPassword($hasher->hashPassword($user, $params['new_password']));

        $user->setRawPassword($params['new_password']);
        $errors = $validator->validate($user);
        $user->eraseCredentials();

        if (count($errors) > 0) {
            $validation_errors = [];
            foreach ($errors as $error) {
                $validation_errors[$error->getPropertyPath()] = $error->getMessage();
            }

            return new Response(content: json_encode([
                "status" => 400,
                "failed_validation" => $validation_errors
            ]), status: Response::HTTP_BAD_REQUEST);
        }

        $EMI->persist($user);
        $EMI->flush();

        return new Response(status: Response::HTTP_ACCEPTED);
    }
}
