const angularModule = angular.module('nodeAuth', [
    'ngRoute'
]);
angularModule.config(['$locationProvider', '$routeProvider', '$httpProvider',
    function ($locationProvider, $routeProvider, $httpProvider) {
        $locationProvider.html5Mode(true);
        $routeProvider.when('/', {
            templateUrl: '/views/home.html'
        }).when('/signin', {
            templateUrl: '/views/signin.html'
        }).when('/profile', {
            templateUrl: '/views/profile.html'
        }).when('/401', {
            templateUrl: '/views/401.html'
        }).otherwise({
            redirectTo: '/'
        });
        $httpProvider.interceptors.push(['$rootScope', '$q', '$location', function ($rootScope, $q, $location) {
            return {
                request: function (config) {
                    if (localStorage.getItem('auth-token')) {
                        config.headers.Authorization = 'bearer ' + localStorage.getItem('auth-token');
                    }
                    return config;
                },
                response: function (response) {
                    const token = response.headers('X-Access-Token');
                    if (token) {
                        localStorage.setItem('auth-token', token);
                        $rootScope.token = token;
                    }
                    return response;
                },
                responseError: function (res) {
                    if (res.status === 401) {
                        $location.url('/401');
                    }
                    return $q.reject(res);
                }
            };
        }]);
    }
]);
angularModule.run(['$rootScope', '$http',
    function ($rootScope, $http) {
        if (localStorage.getItem('auth-token') && !$rootScope.username) {
            return $http.post('/keepsession', {}).then((res) => {
                $rootScope.username = res.data.username;
            }, () => {
                localStorage.removeItem('auth-token');
            });
        }
    }
]);
angularModule.controller('userController', ['$rootScope', '$scope', '$http', '$location',
    function ($rootScope, $scope, $http, $location) {
        $scope.signin = function (valid) {
            if (!valid) {
                $scope.formError = true;
            } else {
                $scope.formError = false;
                $http.post('/signin', {
                    login: $scope.form.login,
                    password: $scope.form.password
                }).then((res) => {
                    if (res.data.token && res.data.username) {
                        localStorage.setItem('auth-token', res.data.token);
                        $rootScope.username = res.data.username;
                        $rootScope.token = res.data.token;
                        $location.path('/');
                    }
                }, () => {
                    $scope.signinForm.login = '';
                    $scope.signinForm.password = '';
                    $scope.formError = true;
                });
            }
        };
    }
]);
angularModule.controller('profileController', ['$scope', '$http',
    function ($scope, $http) {
        $http.get('/profile', {}).then((res) => {
            $scope.realName = res.data.realName;
        });
    }
]);