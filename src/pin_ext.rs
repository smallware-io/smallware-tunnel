use std::pin::Pin;

pub trait PinExt<'a, C> {
    fn pin_field<F>(self: &'a Self, f: fn(&C) -> &F) -> Pin<&'a F>;
}
pub trait PinExtMut<'a, C> {
    fn pin_field<F>(self: &'a Self, f: fn(&C) -> &F) -> Pin<&'a F>;
    fn pin_field_mut<F>(self: &'a Self, f: fn(&C) -> &F) -> Pin<&'a mut F>;
}

impl<'a, C> PinExt<'a, C> for Pin<&'a C> {
    fn pin_field<F>(&'a self, f: fn(&C) -> &F) -> Pin<&'a F> {
        let field_ref: &'a F = f(self);
        // SAFETY: We are not moving the data, just creating a new Pin reference to the field.
        unsafe { Pin::new_unchecked(field_ref) }
    }
}

impl<'a, C> PinExtMut<'a, C> for Pin<&'a mut C> {
    fn pin_field<F>(&'a self, f: fn(&C) -> &F) -> Pin<&'a F> {
        let field_ref: &'a F = f(self);
        // SAFETY: We are not moving the data, just creating a new Pin reference to the field.
        unsafe { Pin::new_unchecked(field_ref) }
    }

    fn pin_field_mut<F>(self: &'a Self, f: fn(&C) -> &F) -> Pin<&'a mut F> {
        let field_ref: &'a F = f(self);
        // SAFETY: We are not moving the data, just creating a new Pin reference to the field.
        unsafe { Pin::new_unchecked(&mut *(field_ref as *const F as *mut F)) }
    }
}
