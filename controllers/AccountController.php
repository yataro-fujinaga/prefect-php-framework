<?php

/**
 * AccountController.
 *
 * @author Katsuhiro Ogawa <fivestar@nequal.jp>
 */
class AccountController extends Controller
{
    protected $auth_actions = array('index', 'signout', 'follow');

    public function signupAction()
    {
        // ログインしている場合
        if ($this->session->isAuthenticated()) {
            // /accountにredirectする
            return $this->redirect('/account');
        }

        return $this->render(array(
            'user_name' => '',
            'password'  => '',
            '_token'    => $this->generateCsrfToken('account/signup'),
        ));
    }

    public function registerAction()
    {
        // ログインしている場合
        if ($this->session->isAuthenticated()) {
            // /accountにredirectする
            return $this->redirect('/account');
        }

        // requestがPOSTではない場合
        if (!$this->request->isPost()) {
            // status code:404を投げる
            $this->forward404();
        }

        // tokenを取得
        $token = $this->request->getPost('_token');
        // CSRF Tokenを確認
        if (!$this->checkCsrfToken('account/signup', $token)) {
            // CSRF Tokenがない場合
            // /account/signupにredirectする
            return $this->redirect('/account/signup');
        }

        // ユーザーネーム、パスワードを取得
        $user_name = $this->request->getPost('user_name');
        $password = $this->request->getPost('password');

        // validate処理
        $errors = array();

        if (!strlen($user_name)) {
            $errors[] = 'ユーザIDを入力してください';
        } else if (!preg_match('/^\w{3,20}$/', $user_name)) {
            $errors[] = 'ユーザIDは半角英数字およびアンダースコアを3 ～ 20 文字以内で入力してください';
        } else if (!$this->db_manager->get('User')->isUniqueUserName($user_name)) {
            $errors[] = 'ユーザIDは既に使用されています';
        }

        if (!strlen($password)) {
            $errors[] = 'パスワードを入力してください';
        } else if (4 > strlen($password) || strlen($password) > 30) {
            $errors[] = 'パスワードは4 ～ 30 文字以内で入力してください';
        }

        // validate処理を通過した場合
        if (count($errors) === 0) {
            // ユーザー情報をDBに登録する
            $this->db_manager->get('User')->insert($user_name, $password);
            // ユーザーをログイン済みにする
            $this->session->setAuthenticated(true);

            // ユーザー情報をDBから取得する
            $user = $this->db_manager->get('User')->fetchByUserName($user_name);
            // ユーザー情報をSessionに保存する
            $this->session->set('user', $user);

            // /にredirectする
            return $this->redirect('/');
        }

        // ログイン画面を表示
        return $this->render(array(
            'user_name' => $user_name,
            'password'  => $password,
            'errors'    => $errors,
            '_token'    => $this->generateCsrfToken('account/signup'),
        ), 'signup');
    }

    public function indexAction()
    {
        // sessionからuserを取得
        $user = $this->session->get('user');
        // userのフォロワーを取得
        $followings = $this->db_manager->get('User')
            ->fetchAllFollowingsByUserId($user['id']);

        return $this->render(array(
            'user'       => $user,
            'followings' => $followings,
        ));
    }

    public function signinAction()
    {
        if ($this->session->isAuthenticated()) {
            return $this->redirect('/account');
        }

        return $this->render(array(
            'user_name' => '',
            'password'  => '',
            '_token'    => $this->generateCsrfToken('account/signin'),
        ));
    }

    public function authenticateAction()
    {
        // ログインしている場合
        if ($this->session->isAuthenticated()) {
            // /accountにredirectする
            return $this->redirect('/account');
        }

        // requestがPOSTではない場合
        if (!$this->request->isPost()) {
            // status code:404
            $this->forward404();
        }

        // tokenを取得
        $token = $this->request->getPost('_token');

        // CSRF Tokenを確認
        if (!$this->checkCsrfToken('account/signin', $token)) {
            // CSRF Tokenがない場合
            // /account/signinにredirectする
            return $this->redirect('/account/signin');
        }

        $user_name = $this->request->getPost('user_name');
        $password = $this->request->getPost('password');

        $errors = array();

        if (!strlen($user_name)) {
            $errors[] = 'ユーザIDを入力してください';
        }

        if (!strlen($password)) {
            $errors[] = 'パスワードを入力してください';
        }

        if (count($errors) === 0) {
            $user_repository = $this->db_manager->get('User');
            // DBをユーザーネームで検索
            $user = $user_repository->fetchByUserName($user_name);


            // ユーザーが存在しない、または
            // パスワードが正しくない場合
            if (!$user
                || ($user['password'] !== $user_repository->hashPassword($password))
            ) {
                $errors[] = 'ユーザIDかパスワードが不正です';
            } else {
                // ユーザーが存在し、パスワードが正しい場合
                // sessionにログインしたことを保存する
                $this->session->setAuthenticated(true);
                // sessionにuser情報を保存する
                $this->session->set('user', $user);

                return $this->redirect('/');
            }
        }

        return $this->render(array(
            'user_name' => $user_name,
            'password'  => $password,
            'errors'    => $errors,
            '_token'    => $this->generateCsrfToken('account/signin'),
        ), 'signin');
    }

    public function signoutAction()
    {
        // sessionを削除する
        $this->session->clear();
        // ログインしていないことをsessionに保存する
        $this->session->setAuthenticated(false);

        return $this->redirect('/account/signin');
    }

    public function followAction()
    {
        if (!$this->request->isPost()) {
            $this->forward404();
        }

        $following_name = $this->request->getPost('following_name');
        if (!$following_name) {
            $this->forward404();
        }

        $token = $this->request->getPost('_token');
        if (!$this->checkCsrfToken('account/follow', $token)) {
            return $this->redirect('/user/' . $following_name);
        }

        $follow_user = $this->db_manager->get('User')
            ->fetchByUserName($following_name);
        if (!$follow_user) {
            $this->forward404();
        }

        $user = $this->session->get('user');

        $following_repository = $this->db_manager->get('Following');
        if ($user['id'] !== $follow_user['id'] 
            && !$following_repository->isFollowing($user['id'], $follow_user['id'])
        ) {
            $following_repository->insert($user['id'], $follow_user['id']);
        }

        return $this->redirect('/account');
    }
}
