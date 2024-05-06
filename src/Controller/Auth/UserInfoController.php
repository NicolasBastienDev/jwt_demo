<?php

namespace App\Controller\Auth;

use App\Entity\User as AppUser;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Bundle\SecurityBundle\Security;

use App\Repository\UserRepository;

class UserInfoController extends AbstractController
{
    public function __construct(private Security $security, private UserRepository $userRepository)
    {
    }

    /**
     * attention security User is not always filled. It depends on the UserProvider used (JWT, ...)
     */
    public function __invoke(): AppUser
    {
        $user = $this->security->getUser();
        if ($user instanceof AppUser && $user->getEmail()) {
            $user = $this->userRepository->findOneBy(array('email' => $user->getEmail()));
        }
        return $user;
    }
}
