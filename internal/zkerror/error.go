package zkerror

import "errors"

//ErrUserHasReachedTheMaximumNumberOfAttempts holds an error for the case when users reach the limit number of a attempts in an hour.
var ErrUserHasReachedTheMaximumNumberOfAttempts = errors.New("You have reached the maximum number of attempts per hour")
